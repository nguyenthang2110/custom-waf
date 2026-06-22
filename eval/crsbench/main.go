// crsbench replays the EXACT same CSIC-2010 test split that cmd/wafbench
// exports (eval/results/test_records.jsonl) through a stock OWASP Core Rule Set
// (CRS) running on the Coraza engine, at paranoia level 1 with the default
// inbound anomaly threshold (5). It reports the same metric suite as wafbench
// so the proposed WAF and the de-facto OSS baseline can be compared
// apples-to-apples on identical records.
//
// This is an evaluation harness, deliberately kept in its OWN Go module so the
// heavy Coraza/CRS dependency tree never enters the main WAF go.mod.
//
//	cd eval/crsbench && go run . -in ../results/test_records.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/corazawaf/coraza/v3"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
)

// injectionClasses mirrors cmd/wafbench: the attack categories a signature WAF
// is designed to catch. The rest of the CSIC anomalous traffic is
// non-injection anomaly and is reported separately.
var injectionClasses = map[string]bool{
	"sqli": true, "xss": true, "traversal": true,
	"rce": true, "crlf": true, "ssi_xxe": true,
}

type rec struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Body        string `json:"body"`
	UserAgent   string `json:"user_agent"`
	Cookie      string `json:"cookie"`
	ContentType string `json:"content_type"`
	Label       string `json:"label"`    // "attack" | "benign"
	Category    string `json:"category"` // sqli/xss/... | benign
}

type confusion struct{ TP, FP, TN, FN int }

func (c confusion) recall() float64 {
	if c.TP+c.FN == 0 {
		return 0
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}
func (c confusion) fpr() float64 {
	if c.FP+c.TN == 0 {
		return 0
	}
	return float64(c.FP) / float64(c.FP+c.TN)
}
func (c confusion) precision() float64 {
	if c.TP+c.FP == 0 {
		return 0
	}
	return float64(c.TP) / float64(c.TP+c.FP)
}
func (c confusion) f1() float64 {
	p, r := c.precision(), c.recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}
func (c confusion) balancedAcc() float64 {
	tnr := 0.0
	if c.FP+c.TN > 0 {
		tnr = float64(c.TN) / float64(c.FP+c.TN)
	}
	return (c.recall() + tnr) / 2
}

// blocked runs one request through CRS and returns whether the engine raised a
// blocking interruption (anomaly score >= inbound threshold).
func blocked(waf coraza.WAF, r rec) bool {
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	tx.ProcessConnection("203.0.113.42", 54321, "127.0.0.1", 8080)
	tx.ProcessURI(r.URL, r.Method, "HTTP/1.1")

	tx.AddRequestHeader("Host", "localhost:8080")
	if r.UserAgent != "" {
		tx.AddRequestHeader("User-Agent", r.UserAgent)
	}
	if r.Cookie != "" {
		tx.AddRequestHeader("Cookie", r.Cookie)
	}
	ct := r.ContentType
	if ct == "" && r.Body != "" {
		ct = "application/x-www-form-urlencoded"
	}
	if ct != "" {
		tx.AddRequestHeader("Content-Type", ct)
	}
	if r.Body != "" {
		tx.AddRequestHeader("Content-Length", fmt.Sprintf("%d", len(r.Body)))
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return true
	}
	if r.Body != "" {
		if _, _, err := tx.WriteRequestBody([]byte(r.Body)); err != nil {
			return tx.Interruption() != nil
		}
	}
	// ProcessRequestBody MUST be called even for empty bodies: the CRS
	// SQLi/XSS/RCE rules run in phase 2, which fires here. Skipping it for GET
	// requests (most CSIC injections) would leave those rules unevaluated.
	if it, err := tx.ProcessRequestBody(); err == nil && it != nil {
		return true
	}
	return tx.Interruption() != nil
}

func main() {
	in := flag.String("in", "../results/test_records.jsonl", "shared test-set JSONL exported by wafbench")
	out := flag.String("out", "../results/run-crs-baseline.json", "metrics output JSON")
	limit := flag.Int("limit", 0, "max records (0 = all)")
	flag.Parse()

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
`),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: build CRS WAF: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Open(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: open %s: %v\n", *in, err)
		os.Exit(1)
	}
	defer f.Close()

	var full, inj confusion
	perCat := map[string]struct{ total, det int }{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	n := 0
	for scanner.Scan() {
		var r rec
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			continue
		}
		n++
		if *limit > 0 && n > *limit {
			n--
			break
		}
		det := blocked(waf, r)
		attack := r.Label == "attack"

		switch {
		case attack && det:
			full.TP++
		case attack && !det:
			full.FN++
		case !attack && det:
			full.FP++
		default:
			full.TN++
		}

		// injection subset: injection-class attacks + all benign (for FP)
		if !attack || injectionClasses[r.Category] {
			switch {
			case attack && det:
				inj.TP++
			case attack && !det:
				inj.FN++
			case !attack && det:
				inj.FP++
			default:
				inj.TN++
			}
		}

		if attack {
			c := perCat[r.Category]
			c.total++
			if det {
				c.det++
			}
			perCat[r.Category] = c
		}
		if n%2000 == 0 {
			fmt.Fprintf(os.Stderr, "  ...%d processed\n", n)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: scan: %v\n", err)
	}

	line := strings.Repeat("=", 74)
	fmt.Println(line)
	fmt.Printf("OWASP CRS (Coraza) BASELINE — CSIC 2010   (same test split as wafbench)\n")
	fmt.Printf("evaluated=%d  PL1, inbound anomaly threshold=5, SecRuleEngine On\n", n)
	fmt.Println(line)
	pp := func(title string, c confusion) {
		fmt.Printf("\n[%s]\n", title)
		fmt.Printf("  %-12s %6s %6s %6s %6s | %8s %7s %8s %6s %7s\n",
			"op", "TP", "FN", "FP", "TN", "Recall", "FPR", "Precis", "F1", "BalAcc")
		fmt.Printf("  %-12s %6d %6d %6d %6d | %7.2f%% %6.2f%% %7.2f%% %6.3f %6.2f%%\n",
			"CRS-block", c.TP, c.FN, c.FP, c.TN,
			c.recall()*100, c.fpr()*100, c.precision()*100, c.f1(), c.balancedAcc()*100)
	}
	pp("FULL anomalous set (incl. non-injection anomalies)", full)
	pp("INJECTION-CLASS subset (sqli/xss/traversal/rce/crlf/ssi_xxe)", inj)

	fmt.Printf("\n[PER ATTACK CATEGORY] (detection rate)\n")
	cats := make([]string, 0, len(perCat))
	for k := range perCat {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	for _, k := range cats {
		c := perCat[k]
		rate := 0.0
		if c.total > 0 {
			rate = float64(c.det) / float64(c.total) * 100
		}
		fmt.Printf("  %-16s %6d %9.1f%%\n", k, c.total, rate)
	}

	report := map[string]any{
		"engine":        "coraza + owasp-crs",
		"config":        "PL1, inbound anomaly threshold 5, SecRuleEngine On",
		"evaluated":     n,
		"full":          full,
		"injection":     inj,
		"full_metrics":  metricMap(full),
		"inj_metrics":   metricMap(inj),
		"per_category":  perCat,
	}
	jb, _ := json.MarshalIndent(report, "", "  ")
	_ = os.WriteFile(*out, jb, 0o644)
	fmt.Printf("\nwrote %s\n", *out)
}

func metricMap(c confusion) map[string]float64 {
	return map[string]float64{
		"recall_tpr": c.recall(), "fpr": c.fpr(),
		"precision": c.precision(), "f1": c.f1(),
		"balanced_accuracy": c.balancedAcc(),
	}
}
