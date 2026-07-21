package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

//go:embed report_template.html
var reportTemplate string

//go:embed logo.png
var logoPNG []byte

func fmtTS(ts *float64) string {
	if ts == nil {
		return "-"
	}
	return time.Unix(int64(*ts), 0).UTC().Format("2006-01-02 15:04:05") + "Z"
}

func commaInt(n int) string {
	s := itoa(n)
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func renderHTML(r report, outPath string) error {
	payload, err := json.Marshal(r)
	if err != nil {
		return err
	}

	span := ""
	if r.Stats.SpanStart != nil && r.Stats.SpanEnd != nil {
		span = fmtTS(r.Stats.SpanStart) + " → " + fmtTS(r.Stats.SpanEnd)
	}
	imperfectPct := round3(100 - r.Stats.PerfectPct)

	logoURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(logoPNG)

	repl := strings.NewReplacer(
		"__LOGO__", logoURI,
		"__PAYLOAD__", string(payload),
		"__LOG_SOURCE__", r.Stats.LogSource,
		"__BEACON_URL__", r.Stats.BeaconURL,
		"__SPAN__", span,
		"__TOTAL__", commaInt(r.Stats.Total),
		"__IMPERFECT_PCT__", trimFloat(imperfectPct),
		"__IMPERFECT__", commaInt(r.Stats.Imperfect),
		"__PERFECT_PCT__", trimFloat(r.Stats.PerfectPct),
		"__HEAD_FALSE__", commaInt(r.Stats.HeadFalse),
		"__SOURCE_FALSE__", commaInt(r.Stats.SourceFalse),
		"__TARGET_FALSE__", commaInt(r.Stats.TargetFalse),
	)
	html := repl.Replace(reportTemplate)
	return os.WriteFile(outPath, []byte(html), 0o644)
}

func trimFloat(f float64) string {
	s := fmt.Sprintf("%.3f", f)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}

func writeJSON(r report, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
