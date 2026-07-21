package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"
)

const (
	// fetchAttempts is how many times a slot is requested before it is recorded
	// as unknown.
	fetchAttempts = 5

	// fetchBackoff is multiplied by the attempt number to space out retries.
	fetchBackoff = 1500 * time.Millisecond

	// emptySlotWalkback bounds how far canonicalHeadRoot walks back over empty
	// slots. Past a full epoch of missed blocks the target vote would be gone
	// too, so the head vote is no longer the interesting question.
	emptySlotWalkback = 32
)

// slotInfo mirrors the beacon_cache.json shape (compatible with any producer).
type slotInfo struct {
	Present    *bool  `json:"present"`
	Root       string `json:"root,omitempty"`
	ParentRoot string `json:"parent_root,omitempty"`
	Proposer   string `json:"proposer,omitempty"`
}

type beacon struct {
	base      string
	cachePath string
	client    *http.Client
	cache     map[string]slotInfo

	// dirty tracks slots resolved after prefetch, so the cache is only rewritten
	// when the walkback actually added something.
	dirty bool
}

func newBeacon(base, cachePath string) *beacon {
	beacon := &beacon{
		base:      trimSlash(base),
		cachePath: cachePath,
		client:    &http.Client{Timeout: 20 * time.Second},
		cache:     make(map[string]slotInfo),
	}

	if data, err := os.ReadFile(cachePath); err == nil {
		_ = json.Unmarshal(data, &beacon.cache)
	}

	return beacon
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}

	return s
}

func boolp(v bool) *bool { return &v }

// fetchOnce runs a single attempt against url. Any returned error means the
// attempt should be retried; a 404 is a definitive answer, not a failure,
// because it means the slot was missed.
func (b *beacon) fetchOnce(url string) (slotInfo, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return slotInfo{}, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return slotInfo{}, fmt.Errorf("do request: %w", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "[beacon] warning: close response body: %v\n", err)
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return slotInfo{Present: boolp(false)}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return slotInfo{}, fmt.Errorf("unexpected status %q", resp.Status)
	}

	var payload struct {
		Data struct {
			Root   string `json:"root"`
			Header struct {
				Message struct {
					ParentRoot string `json:"parent_root"`
					Proposer   string `json:"proposer_index"`
				} `json:"message"`
			} `json:"header"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return slotInfo{}, fmt.Errorf("decode response: %w", err)
	}

	return slotInfo{
		Present:    boolp(true),
		Root:       payload.Data.Root,
		ParentRoot: payload.Data.Header.Message.ParentRoot,
		Proposer:   payload.Data.Header.Message.Proposer,
	}, nil
}

// fetch queries /eth/v1/beacon/headers/{slot}, retrying with a linear backoff.
func (b *beacon) fetch(slot int) slotInfo {
	url := fmt.Sprintf("%s/eth/v1/beacon/headers/%d", b.base, slot)
	for attempt := range fetchAttempts {
		slotInfo, err := b.fetchOnce(url)
		if err == nil {
			return slotInfo
		}

		fmt.Fprintf(os.Stderr, "[beacon] warning: slot %d attempt %d/%d: %v\n", slot, attempt+1, fetchAttempts, err)
		time.Sleep(time.Duration(attempt+1) * fetchBackoff)
	}

	return slotInfo{Present: nil} // unknown (network failure)
}

// prefetch resolves every requested slot, using the on-disk cache when possible.
func (b *beacon) prefetch(slots []int) error {
	var todo []int
	for _, slot := range slots {
		if _, ok := b.cache[itoa(slot)]; !ok {
			todo = append(todo, slot)
		}
	}

	if len(todo) == 0 {
		return nil
	}

	sort.Ints(todo)
	fmt.Fprintf(os.Stderr, "[beacon] fetching %d slots (%d cached)...\n", len(todo), len(slots)-len(todo))

	for i, slot := range todo {
		b.cache[itoa(slot)] = b.fetch(slot)
		if (i+1)%100 != 0 {
			continue
		}

		fmt.Fprintf(os.Stderr, "[beacon]   %d/%d\n", i+1, len(todo))

		// An intermediate checkpoint only saves work on the next run, so a
		// failure is worth reporting but not worth abandoning the fetch for.
		if err := b.save(); err != nil {
			fmt.Fprintf(os.Stderr, "[beacon] warning: checkpoint: %v\n", err)
		}
	}

	if err := b.save(); err != nil {
		return fmt.Errorf("save cache: %w", err)
	}

	return nil
}

func (b *beacon) save() error {
	data, err := json.Marshal(b.cache)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	if err := os.WriteFile(b.cachePath, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", b.cachePath, err)
	}

	return nil
}

// flush writes the cache when the walkback resolved slots prefetch did not
// cover. It is a no-op otherwise.
func (b *beacon) flush() error {
	if !b.dirty {
		return nil
	}

	if err := b.save(); err != nil {
		return fmt.Errorf("save cache: %w", err)
	}

	b.dirty = false

	return nil
}

func (b *beacon) get(slot int) slotInfo {
	return b.cache[itoa(slot)]
}

// resolve returns a slot from the cache, fetching it if prefetch did not cover
// it. Only the empty-slot walkback needs this, so the extra requests stay rare.
func (b *beacon) resolve(slot int) slotInfo {
	if info, ok := b.cache[itoa(slot)]; ok {
		return info
	}

	info := b.fetch(slot)
	b.cache[itoa(slot)] = info
	b.dirty = true

	return info
}

// canonicalHeadRoot returns the block root that a correct head vote for slot
// must carry. That is the root of the block at slot, or, when the slot is
// empty, the root of the most recent block before it: the same answer as the
// spec's get_block_root_at_slot, which repeats the latest block root over
// empty slots.
//
// The second return value is false when the answer cannot be established: a
// network failure left a slot unknown, or the walkback ran past its bound. An
// unknown head root must stay unknown rather than compare unequal.
func (b *beacon) canonicalHeadRoot(slot int) (string, bool) {
	for back := 0; back <= emptySlotWalkback; back++ {
		info := b.resolve(slot - back)
		if info.Present == nil {
			return "", false
		}

		if *info.Present {
			return info.Root, true
		}
	}

	fmt.Fprintf(os.Stderr, "[beacon] warning: slot %d is preceded by more than %d empty slots, head root unresolved\n", slot, emptySlotWalkback)

	return "", false
}
