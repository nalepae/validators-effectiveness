package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	slotsPerEpoch  = 32
	slotsPerPeriod = 2048
	deadlineSecs   = 4.0
)

var (
	kvRe   = regexp.MustCompile(`(\w+)=("(?:[^"]*)"|\[[^\]]*\]|\S+)`)
	timeRe = regexp.MustCompile(`time="([^"]+)"`)
	hexRe  = regexp.MustCompile(`0x[0-9a-fA-F]+`)
)

// parseKV extracts logfmt-style key=value pairs (quoted or bracketed).
func parseKV(line string) map[string]string {
	d := make(map[string]string)
	for _, m := range kvRe.FindAllStringSubmatch(line, -1) {
		v := m[2]
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}

		d[m[1]] = v
	}

	return d
}

// parseTS returns the log line time as unix seconds (float, UTC).
func parseTS(line string) (float64, bool) {
	m := timeRe.FindStringSubmatch(line)
	if m == nil {
		return 0, false
	}

	raw := m[1]
	for _, layout := range []string{"2006-01-02 15:04:05.99", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			return float64(t.UnixNano()) / 1e9, true
		}
	}

	return 0, false
}

// parseDuration parses a Go duration such as "4.006159601s" or "696.431µs".
func parseDuration(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}

	type u struct {
		suf  string
		mult float64
	}

	for _, unit := range []u{{"ms", 1e-3}, {"µs", 1e-6}, {"us", 1e-6}, {"ns", 1e-9}, {"s", 1.0}} {
		if num, ok := strings.CutSuffix(s, unit.suf); ok {
			if f, err := strconv.ParseFloat(num, 64); err == nil {
				return f * unit.mult, true
			}

			return 0, false
		}
	}

	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, true
	}

	return 0, false
}

type logLine struct {
	kv        map[string]string
	timestamp float64
}

type parsedLog struct {
	summaries         []logLine         // "Previous epoch voting summary"
	submissions       []logLine         // "Submitted new attestations"
	headEvents        map[int][]float64 // slot -> sinceSlotStartTime of each head event, in seconds
	requestErrors     []logLine         // "Could not request attestation to sign"
	validatorIdx      map[string]string // short pubkey -> validator index ("Validator activated")
	lastReboot        float64           // ts of the latest "Prysm Validator started" (0 if none)
	streamGaps        int
	headEventsUntimed int
	files             []string // base names of the ingested files, in chronological order
	lastTS            float64  // ts of the last timestamped line seen so far
}

// isLogName reports whether a directory entry looks like a validator log file.
// Prysm rotates "validator.log" into "validator-<timestamp>.log", optionally
// gzipped.
func isLogName(name string) bool {
	if strings.HasPrefix(name, ".") {
		return false
	}

	name = strings.TrimSuffix(name, ".gz")
	return strings.HasSuffix(name, ".log")
}

// openLog opens a log file, transparently decompressing ".gz" ones. The
// returned closer must be called by the caller.
func openLog(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(path, ".gz") {
		return f, nil
	}

	zr, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}

	return struct {
		io.Reader
		io.Closer
	}{Reader: zr, Closer: f}, nil
}

// firstTS returns the timestamp of the first timestamped line of a log file.
// Files without any timestamp sort last (returns +Inf).
func firstTS(path string) float64 {
	rc, err := openLog(path)
	if err != nil {
		return math.Inf(1)
	}

	defer rc.Close()

	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		if ts, ok := parseTS(sc.Text()); ok {
			return ts
		}
	}

	if err := sc.Err(); err != nil {
		return math.Inf(1) // reported by readFile, which reads the whole file
	}

	return math.Inf(1)
}

// logFilesIn returns the log files of a directory, ordered chronologically by
// their first log line, so that concatenating them yields a single monotonic
// stream.
func logFilesIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}

	var paths []string
	for _, e := range entries {
		if e.IsDir() || !isLogName(e.Name()) {
			continue
		}

		paths = append(paths, filepath.Join(dir, e.Name()))
	}

	if len(paths) == 0 {
		return nil, fmt.Errorf("no *.log or *.log.gz file found in %s", dir)
	}

	starts := make(map[string]float64, len(paths))
	for _, path := range paths {
		starts[path] = firstTS(path)
	}

	sort.Slice(paths, func(i, j int) bool {
		if starts[paths[i]] != starts[paths[j]] {
			return starts[paths[i]] < starts[paths[j]]
		}

		return paths[i] < paths[j]
	})

	return paths, nil
}

// loadLogs parses every log file of a directory as one concatenated log. If
// path is a regular file, that single file is parsed.
func loadLogs(path string) (*parsedLog, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	paths := []string{path}
	if st.IsDir() {
		if paths, err = logFilesIn(path); err != nil {
			return nil, fmt.Errorf("log files in: %w", err)
		}
	}

	p := &parsedLog{headEvents: make(map[int][]float64), validatorIdx: make(map[string]string)}
	for _, fp := range paths {
		base := filepath.Base(fp)
		fmt.Fprintf(os.Stderr, "[parse] reading %s...\n", base)
		if p.lastTS > 0 {
			if ts := firstTS(fp); ts < p.lastTS {
				fmt.Fprintf(os.Stderr,
					"[parse] warning: %s starts at %s, before the end of the previous file (%s); overlapping lines will be counted twice\n",
					base, fmtUTC(ts), fmtUTC(p.lastTS))
			}
		}

		if err := p.readFile(fp); err != nil {
			return nil, fmt.Errorf("read file: %w", err)
		}

		p.files = append(p.files, base)
	}

	if p.headEventsUntimed > 0 {
		fmt.Fprintf(os.Stderr,
			"[parse] warning: %d head events carry no sinceSlotStartTime field and were ignored\n",
			p.headEventsUntimed)
	}

	return p, nil
}

func fmtUTC(ts float64) string {
	return time.Unix(int64(ts), 0).UTC().Format("2006-01-02 15:04:05") + "Z"
}

// readFile parses one log file, appending to p. Files must be read in
// chronological order: "Prysm Validator started" keeps only the latest match.
func (p *parsedLog) readFile(path string) error {
	f, err := openLog(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	lastRaw := ""
	for sc.Scan() {
		raw := sc.Text()
		lastRaw = raw
		switch {
		case strings.Contains(raw, "Previous epoch voting summary"):
			d := parseKV(raw)
			ts, _ := parseTS(raw)
			p.summaries = append(p.summaries, logLine{d, ts})
		case strings.Contains(raw, "Submitted new attestations"):
			d := parseKV(raw)
			ts, _ := parseTS(raw)
			p.submissions = append(p.submissions, logLine{d, ts})
		case strings.Contains(raw, "Received head event"), strings.Contains(raw, "Received head_v2 event"):
			d := parseKV(raw)
			slot, err := strconv.Atoi(d["slot"])
			if err != nil {
				break // stream keep-alive with no slot to attribute
			}

			off, ok := parseDuration(d["sinceSlotStartTime"])
			if !ok {
				p.headEventsUntimed++ // pre-2026-07-20 format, cannot be timed
				break
			}

			p.headEvents[slot] = append(p.headEvents[slot], off)
		case strings.Contains(raw, "Could not request attestation to sign"):
			d := parseKV(raw)
			ts, _ := parseTS(raw)
			p.requestErrors = append(p.requestErrors, logLine{d, ts})
		case strings.Contains(raw, "Validator activated"):
			d := parseKV(raw)
			if pk, idx := d["pubkey"], d["validatorIndex"]; pk != "" && idx != "" {
				p.validatorIdx[pk] = idx
			}
		case strings.Contains(raw, "Prysm Validator started"):
			if ts, ok := parseTS(raw); ok {
				p.lastReboot = ts // log is chronological, so the last one wins
			}
		case strings.Contains(raw, "event stream disconnected"), strings.Contains(raw, "event stream reported an error"):
			p.streamGaps++
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}

	if ts, ok := parseTS(lastRaw); ok {
		p.lastTS = ts
	}

	return nil
}
