package main

import "testing"

// newTestBeacon builds a beacon whose cache is pre-seeded, so canonicalHeadRoot
// resolves every slot locally and never reaches the network.
func newTestBeacon(t *testing.T, cache map[string]slotInfo) *beacon {
	t.Helper()

	return &beacon{
		base:      "http://beacon.invalid",
		cachePath: t.TempDir() + "/cache.json",
		cache:     cache,
	}
}

func present(root string) slotInfo { return slotInfo{Present: boolp(true), Root: root} }

var (
	absent  = slotInfo{Present: boolp(false)}
	unknown = slotInfo{Present: nil}
)

func TestCanonicalHeadRoot(t *testing.T) {
	tests := []struct {
		name     string
		cache    map[string]slotInfo
		slot     int
		wantRoot string
		wantOK   bool
	}{
		{
			name:     "block at the attested slot",
			cache:    map[string]slotInfo{"100": present("0xaaaa")},
			slot:     100,
			wantRoot: "0xaaaa",
			wantOK:   true,
		},
		{
			name:     "empty attested slot walks back one",
			cache:    map[string]slotInfo{"100": absent, "99": present("0xbbbb")},
			slot:     100,
			wantRoot: "0xbbbb",
			wantOK:   true,
		},
		{
			name:     "several empty slots in a row",
			cache:    map[string]slotInfo{"100": absent, "99": absent, "98": absent, "97": present("0xcccc")},
			slot:     100,
			wantRoot: "0xcccc",
			wantOK:   true,
		},
		{
			name:   "unknown slot stays unknown rather than walking past it",
			cache:  map[string]slotInfo{"100": absent, "99": unknown, "98": present("0xdddd")},
			slot:   100,
			wantOK: false,
		},
		{
			name:   "unknown attested slot",
			cache:  map[string]slotInfo{"100": unknown},
			slot:   100,
			wantOK: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, ok := newTestBeacon(t, test.cache).canonicalHeadRoot(test.slot)
			if ok != test.wantOK {
				t.Fatalf("ok = %v, want %v", ok, test.wantOK)
			}

			if root != test.wantRoot {
				t.Fatalf("root = %q, want %q", root, test.wantRoot)
			}
		})
	}
}

// Past the bound the walkback must give up instead of scanning forever, and it
// must not claim a root it never found.
func TestCanonicalHeadRootWalkbackBound(t *testing.T) {
	const slot = 1000

	cache := make(map[string]slotInfo, emptySlotWalkback+2)
	for back := 0; back <= emptySlotWalkback; back++ {
		cache[itoa(slot-back)] = absent
	}

	cache[itoa(slot-emptySlotWalkback-1)] = present("0xeeee")

	root, ok := newTestBeacon(t, cache).canonicalHeadRoot(slot)
	if ok || root != "" {
		t.Fatalf("canonicalHeadRoot = (%q, %v), want (\"\", false)", root, ok)
	}
}

// An empty attested slot must not make a correct head vote look wrong: the
// expected root moves back to the last block before it.
func TestLateInclusionSurvivesEmptyAttestedSlot(t *testing.T) {
	b := newTestBeacon(t, map[string]slotInfo{
		"100": absent,
		"99":  present("0xbbbbccccdddd0000"),
		"101": present("0xffff"),
	})

	expected, ok := b.canonicalHeadRoot(100)
	if !ok {
		t.Fatal("canonicalHeadRoot: want the preceding block to resolve")
	}

	votedHead := "0xbbbbccccdddd" // the truncated root the validator client logs
	if !hasRootPrefix(expected, votedHead) {
		t.Fatalf("hasRootPrefix(%q, %q) = false, want true", expected, votedHead)
	}

	votedCanonical := true
	r := record{
		HeadOK:         false,
		TargetOK:       true,
		SourceOK:       true,
		VotedCanonical: &votedCanonical,
	}

	if !lateInclusion(r, false) {
		t.Fatal("lateInclusion = false, want true for a canonical vote on an empty slot")
	}
}
