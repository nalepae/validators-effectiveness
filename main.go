// Command validator-perfs analyses a directory of active-active validator
// client logs (concatenated in chronological order) and produces an HTML
// report of every attestation that was not perfect (correct
// head, target and source), classifying each by root cause.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// parseRangeTime accepts a few common UTC timestamp forms and returns unix
// seconds. An empty string means "unbounded" (returns 0).
func parseRangeTime(s string) (float64, error) {
	if s == "" {
		return 0, nil
	}
	layouts := []string{
		"2006-01-02 15:04:05", "2006-01-02T15:04:05",
		"2006-01-02 15:04", "2006-01-02T15:04",
		"2006-01-02", time.RFC3339,
	}

	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return float64(t.Unix()), nil
		}
	}

	return 0, fmt.Errorf("unrecognized time %q (try \"2006-01-02 15:04:05\" UTC)", s)
}

func main() {
	logPath := flag.String("vc-logs-dir", "", "path to the directory holding the validator client log files, which are concatenated in chronological order (required)")
	beaconURL := flag.String("beacon", "https://ethereum-beacon-api.publicnode.com", "beacon node base URL")
	out := flag.String("out", "report.html", "output HTML path")
	startStr := flag.String("start", "", "only include attestations logged at/after this UTC time, or \"latest-reboot\" (default: start of log)")
	endStr := flag.String("end", "", "only include attestations logged at/before this UTC time (default: end of log)")
	flag.Parse()

	if *logPath == "" {
		fmt.Fprintln(os.Stderr, "error: --vc-logs-dir is required")
		flag.Usage()
		os.Exit(2)
	}

	latestReboot := *startStr == "latest-reboot"
	var start float64
	if !latestReboot {
		var err error
		if start, err = parseRangeTime(*startStr); err != nil {
			fmt.Fprintf(os.Stderr, "error: --start %v\n", err)
			os.Exit(2)
		}
	}

	end, err := parseRangeTime(*endStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --end %v\n", err)
		os.Exit(2)
	}

	logsDir := *logPath
	outPath := *out

	parsedLog, err := loadLogs(logsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading logs: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(
		os.Stderr, "[parse] %d file(s), %d summaries, %d submissions, %d head-event slots\n",
		len(parsedLog.files), len(parsedLog.summaries), len(parsedLog.submissions), len(parsedLog.headEvents),
	)

	if latestReboot {
		if parsedLog.lastReboot == 0 {
			fmt.Fprintln(os.Stderr, "error: --start latest-reboot: no \"Prysm Validator started\" line found in the logs")
			os.Exit(2)
		}

		start = parsedLog.lastReboot
		fmt.Fprintf(os.Stderr, "[range] latest reboot at %s\n", time.Unix(int64(start), 0).UTC().Format("2006-01-02 15:04:05")+"Z")
	}

	if start > 0 && end > 0 && end < start {
		fmt.Fprintln(os.Stderr, "error: --end is before --start")
		os.Exit(2)
	}

	idx := buildIndex(parsedLog.submissions)
	need := slotsNeeded(parsedLog, idx, start, end)

	cacheDir := filepath.Dir(outPath)
	if cacheDir == "" {
		cacheDir = "."
	}
	b := newBeacon(*beaconURL, filepath.Join(cacheDir, "beacon_cache.json"))

	// The cache only speeds up later runs, so losing it must not discard the
	// analysis the fetched slots just paid for.
	if err := b.prefetch(need); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}

	source := filepath.Base(logsDir)
	if len(parsedLog.files) > 1 {
		source = fmt.Sprintf("%s (%d files)", source, len(parsedLog.files))
	}

	rep := analyse(parsedLog, b, source, *beaconURL, parsedLog.validatorIdx, start, end)

	// The empty-slot walkback resolves slots on demand, past what prefetch saved.
	if err := b.flush(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}

	jsonPath := outPath[:len(outPath)-len(filepath.Ext(outPath))] + ".json"
	if err := writeJSON(rep, jsonPath); err != nil {
		fmt.Fprintf(os.Stderr, "error writing json: %v\n", err)
		os.Exit(1)
	}

	if err := renderHTML(rep, outPath); err != nil {
		fmt.Fprintf(os.Stderr, "error writing html: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== summary ===\n")
	fmt.Printf("total attestations : %d\n", rep.Stats.Total)
	fmt.Printf("imperfect          : %d  (%.3f%%)\n", rep.Stats.Imperfect, 100-rep.Stats.PerfectPct)
	type reasonCount struct {
		cause reason
		count int
	}

	var counts []reasonCount
	for cause, count := range rep.Stats.ReasonCounts {
		counts = append(counts, reasonCount{cause, count})
	}

	sort.Slice(counts, func(i, j int) bool { return counts[i].count > counts[j].count })
	for _, rc := range counts {
		fmt.Printf("  %-28s : %d\n", rc.cause, rc.count)
	}

	fmt.Printf("\nwrote %s and %s\n", outPath, jsonPath)
}
