package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type reason string

const (
	reasonNotSubmitted   reason = "not_submitted"
	reasonNextSlotMissed reason = "next_slot_missed"
	reasonHeadEventLate  reason = "no_head_event_in_deadline"
	reasonLateInclusion  reason = "late_inclusion"
	reasonOther          reason = "other"
)

// record is one imperfect attestation, serialized straight into the report
// JSON. Its fields stay exported because encoding/json ignores unexported ones.
type record struct {
	Epoch          int      `json:"epoch"`
	Pubkey         string   `json:"pubkey"`
	Slot           *int     `json:"slot"`
	SlotInEpoch    *int     `json:"slot_in_epoch"`
	SlotInPeriod   *int     `json:"slot_in_period"`
	HeadOK         bool     `json:"head_ok"`
	TargetOK       bool     `json:"target_ok"`
	SourceOK       bool     `json:"source_ok"`
	Reason         reason   `json:"reason"`
	Reasons        []reason `json:"reasons"`
	Detail         string   `json:"detail"`
	SinceSlotStart *float64 `json:"since_slot_start"`
	VotedHead      *string  `json:"voted_head"`
	FirstHeadOff   *float64 `json:"first_head_offset"`
	HeadEvents     int      `json:"head_events_count"`
	NextSlotMissed *bool    `json:"next_slot_missed"`
	BlockPresent   *bool    `json:"block_present"`
	VotedCanonical *bool    `json:"voted_canonical"`
}

type stats struct {
	Total          int               `json:"total_attestations"`
	Imperfect      int               `json:"imperfect"`
	Perfect        int               `json:"perfect"`
	PerfectPct     float64           `json:"perfect_pct"`
	HeadFalse      int               `json:"head_false"`
	SourceFalse    int               `json:"source_false"`
	TargetFalse    int               `json:"target_false"`
	ReasonCounts   map[reason]int    `json:"reason_counts"`
	SpanStart      *float64          `json:"span_start"`
	SpanEnd        *float64          `json:"span_end"`
	BeaconURL      string            `json:"beacon_url"`
	LogSource      string            `json:"log_source"`
	StreamGapCount int               `json:"stream_gap_count"`
	ValidatorIndex map[string]string `json:"validator_index"`
}

type report struct {
	Stats   stats    `json:"stats"`
	Records []record `json:"records"`
}

func itoa(i int) string     { return strconv.Itoa(i) }
func isFalse(v string) bool { return v == "false" }

// hasRootPrefix reports whether full (a 32-byte root) starts with short, the
// truncated root logged by the validator client. Callers must reject empty
// roots first: an unknown root must stay unknown, not compare unequal.
func hasRootPrefix(full, short string) bool {
	return len(full) >= len(short) && strings.EqualFold(full[:len(short)], short)
}

// inRange reports whether a log timestamp falls within [start, end].
// A bound of 0 means unbounded.
// A line with no timestamp (ts == 0) is excluded when either bound is set.
func inRange(ts, start, end float64) bool {
	if start == 0 && end == 0 {
		return true
	}

	if ts == 0 {
		return false
	}

	if start > 0 && ts < start {
		return false
	}

	if end > 0 && ts > end {
		return false
	}

	return true
}

// lateInclusion reports whether an inclusion delay greater than one slot is the
// only remaining explanation for a lost timely-head flag.
//
// Altair's TIMELY_HEAD flag needs three things at once: a matching target (which
// implies a matching source), a head vote equal to the canonical block root at
// the attested slot, and an inclusion delay of exactly one slot. When the first
// two hold and slot N+1 was proposed, the third is the only one left to fail:
// the attestation did land on chain, just in a block after N+1, because the
// proposer of N+1 left it out. Source and target are unaffected, since they
// tolerate any inclusion delay within the epoch window.
//
// This is a deduction from the flags, not an observation: the analyser does not
// scan blocks for the attestation, so it reports that the delay exceeded one
// slot without saying by how much.
func lateInclusion(r record, nextMissed bool) bool {
	return !r.HeadOK && r.TargetOK && r.SourceOK &&
		!nextMissed && r.VotedCanonical != nil && *r.VotedCanonical
}

func isImperfect(d logLine) bool {
	return isFalse(d.kv["correctlyVotedHead"]) || isFalse(d.kv["correctlyVotedSource"]) || isFalse(d.kv["correctlyVotedTarget"])
}

// buildIndex maps (targetEpoch, short pubkey) -> submission line.
func buildIndex(subs []logLine) map[string]logLine {
	index := make(map[string]logLine)
	for _, sub := range subs {
		epoch := sub.kv["targetEpoch"]
		for _, pubkey := range hexRe.FindAllString(sub.kv["pubkeys"], -1) {
			index[epoch+"|"+pubkey] = sub
		}
	}

	return index
}

func analyse(p *parsedLog, b *beacon, logSource, beaconURL string, valIndex map[string]string, start, end float64) report {
	// Restrict to the requested time window.
	var summaries []logLine
	for _, summary := range p.summaries {
		if inRange(summary.timestamp, start, end) {
			summaries = append(summaries, summary)
		}
	}

	total := len(summaries)

	var imperfectSummaries []logLine
	for _, summary := range summaries {
		if isImperfect(summary) {
			imperfectSummaries = append(imperfectSummaries, summary)
		}
	}

	idx := buildIndex(p.submissions)

	errBySlot := make(map[int]logLine)
	for _, requestError := range p.requestErrors {
		if slotString, ok := requestError.kv["slot"]; ok {
			if slot, err := strconv.Atoi(slotString); err == nil {
				errBySlot[slot] = requestError
			}
		}
	}

	records := make([]record, 0, len(imperfectSummaries))
	for _, imperfectSummary := range imperfectSummaries {
		epoch, _ := strconv.Atoi(imperfectSummary.kv["epoch"])
		pubkey := imperfectSummary.kv["pubkey"]
		record := record{
			Epoch:    epoch,
			Pubkey:   pubkey,
			HeadOK:   imperfectSummary.kv["correctlyVotedHead"] == "true",
			TargetOK: imperfectSummary.kv["correctlyVotedTarget"] == "true",
			SourceOK: imperfectSummary.kv["correctlyVotedSource"] == "true",
		}

		sub, ok := idx[imperfectSummary.kv["epoch"]+"|"+pubkey]
		if !ok {
			record.Reason = reasonNotSubmitted
			record.Reasons = []reason{reasonNotSubmitted}
			record.Detail = "No 'Submitted new attestations' log found for this validator/epoch."
			lo := epoch * slotsPerEpoch
			for slot := lo; slot < lo+slotsPerEpoch; slot++ {
				if e, ok := errBySlot[slot]; ok && strings.Contains(e.kv["pubkey"], pubkey) {
					record.Slot = &slot
					slotInEpoch := slot % slotsPerEpoch
					record.SlotInEpoch = &slotInEpoch
					slotInPeriod := slot % slotsPerPeriod
					record.SlotInPeriod = &slotInPeriod

					if msg := e.kv["error"]; msg != "" {
						record.Detail = msg
					}

					break
				}
			}

			records = append(records, record)
			continue
		}

		slot, _ := strconv.Atoi(sub.kv["slot"])
		slotInEpoch := slot % slotsPerEpoch
		slotInPeriod := slot % slotsPerPeriod
		record.Slot = &slot
		record.SlotInEpoch = &slotInEpoch
		record.SlotInPeriod = &slotInPeriod

		if since, ok := parseDuration(sub.kv["sinceSlotStartTime"]); ok {
			record.SinceSlotStart = &since
		}

		if votedHead := hexRe.FindString(sub.kv["blockRoot"]); votedHead != "" {
			record.VotedHead = &votedHead
		}

		// head-event timing for this slot: only the earliest event matters
		events := p.headEvents[slot]
		record.HeadEvents = len(events)
		var firstOff *float64
		headInTime := false

		if len(events) > 0 {
			firstEvent := events[0]
			for _, off := range events[1:] {
				firstEvent = min(firstEvent, off)
			}

			firstOff = &firstEvent
			headInTime = firstEvent <= deadlineSecs
		}

		record.FirstHeadOff = firstOff

		// beacon facts
		slotInfo := b.get(slot)
		nextSlotInfo := b.get(slot + 1)
		record.BlockPresent = slotInfo.Present
		if nextSlotInfo.Present != nil {
			nm := !*nextSlotInfo.Present
			record.NextSlotMissed = &nm
		}

		nextMissed := nextSlotInfo.Present != nil && !*nextSlotInfo.Present
		if record.VotedHead != nil {
			// Not slotInfo.Root: an empty slot N does not make the head vote
			// wrong, it moves the expected root back to the last block before N.
			if expected, ok := b.canonicalHeadRoot(slot); ok {
				vc := hasRootPrefix(expected, *record.VotedHead)
				record.VotedCanonical = &vc
			}
		}

		var reasons []reason
		if nextMissed {
			reasons = append(reasons, reasonNextSlotMissed)
		}

		// Ordered before the late-head-event reason on purpose: a canonical head
		// vote proves the validator did see the right head, whatever the head
		// event log does or does not show.
		if lateInclusion(record, nextMissed) {
			reasons = append(reasons, reasonLateInclusion)
		}

		if !headInTime {
			reasons = append(reasons, reasonHeadEventLate)
		}

		if len(reasons) == 0 {
			reasons = append(reasons, reasonOther)
		}

		record.Reasons = reasons
		record.Reason = reasons[0]

		// Where a correct head vote had to point. An empty attested slot moves
		// that target back to the last block before it.
		votedAt := fmt.Sprintf("slot %d", slot)
		if record.BlockPresent != nil && !*record.BlockPresent {
			votedAt = fmt.Sprintf("slot %d (empty, so the block before it)", slot)
		}

		switch record.Reason {
		case reasonNextSlotMissed:
			record.Detail = fmt.Sprintf("Block at slot %d was missed: the attestation for slot %d cannot be included at inclusion-delay 1, so timely head is lost.", slot+1, slot)
		case reasonHeadEventLate:
			if firstOff == nil {
				record.Detail = fmt.Sprintf("No head event for slot %d was ever logged: validator attested with the parent block as head.", slot)
				break
			}

			record.Detail = fmt.Sprintf("Earliest head event for slot %d arrived at +%.3fs, past the %.0fs deadline: the validator attested the parent block as head.", slot, *firstOff, deadlineSecs)
		case reasonLateInclusion:
			record.Detail = fmt.Sprintf("Head vote %s matched the canonical head at %s, but the proposer of slot %d left the attestation out, so it was included at a delay above one slot. Only timely head, which needs exactly one, was lost.", *record.VotedHead, votedAt, slot+1)
		default:
			switch {
			case record.VotedCanonical != nil && !*record.VotedCanonical:
				record.Detail = fmt.Sprintf("Voted head %s does not match the canonical head at %s: either that block was re-orged out, or the in-time head event had not been applied yet when the attestation was built.", *record.VotedHead, votedAt)
			case record.BlockPresent != nil && !*record.BlockPresent:
				record.Detail = fmt.Sprintf("Slot %d itself was missed on-chain.", slot)
			default:
				record.Detail = "Head event arrived in time and the next slot exists: cause is outside the logged signals (likely a late/re-orged block or inclusion issue)."
			}
		}
		records = append(records, record)
	}

	sort.SliceStable(records, func(i, j int) bool {
		si, sj := records[i].Slot, records[j].Slot
		if si == nil {
			return false
		}

		if sj == nil {
			return true
		}

		return *si < *sj
	})

	reasonCounts := map[reason]int{}
	headF, sourceF, targetF := 0, 0, 0
	for _, record := range records {
		reasonCounts[record.Reason]++
		if !record.HeadOK {
			headF++
		}

		if !record.SourceOK {
			sourceF++
		}

		if !record.TargetOK {
			targetF++
		}
	}

	var spanStart, spanEnd *float64
	for _, summary := range summaries {
		if summary.timestamp == 0 {
			continue
		}

		timestamp := summary.timestamp
		if spanStart == nil || timestamp < *spanStart {
			spanStart = &timestamp
		}

		if spanEnd == nil || timestamp > *spanEnd {
			spanEnd = &timestamp
		}
	}

	perfectPct := 0.0
	if total > 0 {
		perfectPct = round3(100.0 * float64(total-len(records)) / float64(total))
	}

	return report{
		Stats: stats{
			Total:          total,
			Imperfect:      len(records),
			Perfect:        total - len(records),
			PerfectPct:     perfectPct,
			HeadFalse:      headF,
			SourceFalse:    sourceF,
			TargetFalse:    targetF,
			ReasonCounts:   reasonCounts,
			SpanStart:      spanStart,
			SpanEnd:        spanEnd,
			BeaconURL:      beaconURL,
			LogSource:      logSource,
			StreamGapCount: p.streamGaps,
			ValidatorIndex: valIndex,
		},
		Records: records,
	}
}

func round3(f float64) float64 {
	return float64(int(f*1000+0.5)) / 1000
}

// slotsNeeded returns every slot (N and N+1) that must be resolved on the beacon,
// restricted to imperfect attestations within the [start, end] window.
func slotsNeeded(p *parsedLog, idx map[string]logLine, start, end float64) []int {
	seen := map[int]bool{}
	for _, summary := range p.summaries {
		if !inRange(summary.timestamp, start, end) || !isImperfect(summary) {
			continue
		}

		if sub, ok := idx[summary.kv["epoch"]+"|"+summary.kv["pubkey"]]; ok {
			if n, err := strconv.Atoi(sub.kv["slot"]); err == nil {
				seen[n] = true
				seen[n+1] = true
			}
		}
	}

	out := make([]int, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}

	sort.Ints(out)
	return out
}
