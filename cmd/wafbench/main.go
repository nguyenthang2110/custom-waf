// cmd/wafbench/main.go
//
// WAF detection benchmark over the HTTP DATASET CSIC 2010.
// ========================================================
// Loads the production rule set through the REAL pipeline
// (parser.Parse -> normalizer.Normalize -> engine.Evaluate) so the numbers
// reflect exactly what the running WAF would decide — no bespoke decoding
// that could inflate detection.
//
// Corpus: HTTP DATASET CSIC 2010 (Giménez et al., CSIC).
//   - normalTrafficTest.txt      -> label "benign"
//   - anomalousTrafficTest.txt   -> label "attack"
//
// Each request is split deterministically (FNV hash of the request) into a
// TRAIN view (shown to the rule-author agent) and a held-out TEST view
// (only the rule-tester agent reports TEST numbers) so rule changes are
// measured as real generalisation, not memorised payloads.
//
// Metrics (standard WAF/IDS evaluation vocabulary):
//
//	confusion matrix TP/FP/TN/FN  → Recall/Detection-Rate (TPR), FPR,
//	Precision, F1, Accuracy, Balanced Accuracy — reported at the two runtime
//	operating points: BLOCK (score>=5, request rejected) and MONITOR (score>0,
//	matched >=1 rule — request forwarded but flagged as suspicious in the log).
//
// Honesty note: the CSIC "anomalous" set mixes injection attacks (SQLi/XSS/
// traversal/RCE/CRLF) with non-injection anomalies (parameter tampering,
// type violations) that a signature WAF is not designed to block. Results are
// therefore reported BOTH over the full anomalous set and over the
// injection-class subset, clearly labelled.
//
// Usage:
//
//	go run ./cmd/wafbench -split test                 # held-out TEST metrics
//	go run ./cmd/wafbench -split train -limit 3000     # author-facing view
//	go run ./cmd/wafbench -split all   -tag final      # full-corpus headline
//
// No production file is modified by this program.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"net/http"
	"os"
	"sort"
	"strings"

	"waf-project/internal/engine"
	"waf-project/internal/normalizer"
	"waf-project/internal/parser"
	"waf-project/internal/training"
)

// Thresholds mirror configs/config.yaml (decision + ml.gray_lower).
const (
	blockThreshold = 5.0
	// MONITOR fires for any request that matched a rule (score > 0). The tiny
	// epsilon makes confAt's ">=" behave like a strict "> 0" (rule scores are
	// either 0 or well above this).
	monitorEpsilon = 1e-9
	testSplitPct   = 40 // 40% TEST, 60% TRAIN — deterministic by hash

	// mlServeTextBudget is the byte budget the LIVE WAF feeds to the canonical
	// text builder before calling the model — it MUST equal ml.max_body_len in
	// configs/config.yaml (the value cmd/waf wires into MLMaxTextLen). Using a
	// smaller value here would truncate body-borne payloads (the canonical
	// layout is "METHOD path\nheaders\n\nbody", so the body is last) and
	// understate the model's real serve-time recall. The model's tokenizer then
	// caps at 256 tokens regardless, so this byte cap rarely bites — it just
	// guarantees the OOD eval sees the same text the deployed model would.
	mlServeTextBudget = 4096
)

// injectionClasses are the attack categories a signature WAF is designed to
// catch; the rest of the CSIC anomalous traffic is non-injection anomaly.
var injectionClasses = map[string]bool{
	"sqli": true, "xss": true, "traversal": true,
	"rce": true, "crlf": true, "ssi_xxe": true,
}

type record struct {
	method, rawURL, body  string
	contentType, ua, cook string
	label                 string // "attack" | "benign"
	category              string // attack signature class, or "benign"
	split                 string // "train" | "test"
}

// ---------------------------------------------------------------------------
// CSIC parsing
// ---------------------------------------------------------------------------

func isReqLine(line string) (method, rawurl string, ok bool) {
	// "METHOD http://host/path?q HTTP/1.1"
	parts := strings.Fields(line)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return "", "", false
	}
	switch parts[0] {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE":
		return parts[0], parts[1], true
	}
	return "", "", false
}

func parseCSIC(path, label string) ([]record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")

	var recs []record
	var cur *record
	var bodyLines []string
	inBody := false

	flush := func() {
		if cur == nil {
			return
		}
		cur.body = strings.TrimSpace(strings.Join(bodyLines, "\n"))
		recs = append(recs, *cur)
		cur = nil
		bodyLines = nil
		inBody = false
	}

	for _, ln := range lines {
		ln = strings.TrimRight(ln, "\r")
		if m, u, ok := isReqLine(ln); ok {
			flush()
			cur = &record{method: m, rawURL: u, label: label}
			continue
		}
		if cur == nil {
			continue
		}
		if !inBody {
			if strings.TrimSpace(ln) == "" {
				inBody = true
				continue
			}
			if k, v, ok := splitHeader(ln); ok {
				switch strings.ToLower(k) {
				case "content-type":
					cur.contentType = v
				case "user-agent":
					cur.ua = v
				case "cookie":
					cur.cook = v
				}
			}
			continue
		}
		bodyLines = append(bodyLines, ln)
	}
	flush()
	return recs, nil
}

func splitHeader(ln string) (k, v string, ok bool) {
	i := strings.Index(ln, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(ln[:i]), strings.TrimSpace(ln[i+1:]), true
}

// ---------------------------------------------------------------------------
// Signature-based attack categorisation (for stratified reporting only — it
// does NOT feed the engine; it just labels which kind of anomaly a request is)
// ---------------------------------------------------------------------------

func ishex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// decodePct best-effort percent-decodes (Latin-1 safe) and turns '+' into
// space, lower-cased — only used to recognise attack signatures.
func decodePct(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '+' {
			b.WriteByte(' ')
			continue
		}
		if c == '%' && i+2 < len(s) && ishex(s[i+1]) && ishex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(c)
	}
	return strings.ToLower(b.String())
}

func categorize(r record) string {
	if r.label == "benign" {
		return "benign"
	}
	s := decodePct(r.rawURL + " " + r.body)
	has := func(subs ...string) bool {
		for _, x := range subs {
			if strings.Contains(s, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("union select", "union all select", " or 1=1", "or '1'='1", "or \"1\"=\"1",
		"drop table", "insert into", "delete from", "information_schema", "sleep(",
		"benchmark(", "waitfor delay", "extractvalue", "updatexml", "load_file",
		"into outfile", "' or ", "\" or ", "' and ", "'; ", "');", "' union", "concat("):
		return "sqli"
	case has("<script", "</script", "onerror=", "onload=", "onmouseover=", "javascript:",
		"<svg", "<iframe", "<img", "alert(", "prompt(", "document.cookie",
		"fromcharcode", "<body", "<object", "<embed"):
		return "xss"
	case has("../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow", "boot.ini",
		"win.ini", "..%2f", "..%5c", "/proc/self"):
		return "traversal"
	case has(";cat ", "|cat", "`", "$(", "/bin/sh", "/bin/bash", "cmd.exe",
		"powershell", "wget ", "; ls", "&&", "||", "ping -", "nc -", "system(", "; id"):
		return "rce"
	case has("%0d%0a", "%0d", "%0a", "\r\n"):
		return "crlf"
	case has("<!entity", "<!doctype", "<?xml", "<%", "${jndi", "%{"):
		return "ssi_xxe"
	default:
		return "anomaly_other"
	}
}

// ---------------------------------------------------------------------------
// Deterministic TRAIN/TEST split
// ---------------------------------------------------------------------------

func splitOf(r record) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(r.method + "|" + r.rawURL + "|" + r.body))
	if int(h.Sum32()%100) < testSplitPct {
		return "test"
	}
	return "train"
}

// ---------------------------------------------------------------------------
// Engine evaluation through the real pipeline
// ---------------------------------------------------------------------------

type evalResult struct {
	rec        record
	score      float64
	matchedIDs []string
	parseErr   bool
}

func scoreRecord(p *parser.HTTPParser, n *normalizer.Normalizer, re *engine.RuleEngine, r record) evalResult {
	var bodyReader *strings.Reader
	if r.body != "" {
		bodyReader = strings.NewReader(r.body)
	}
	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequest(r.method, r.rawURL, bodyReader)
	} else {
		req, err = http.NewRequest(r.method, r.rawURL, nil)
	}
	if err != nil {
		return evalResult{rec: r, parseErr: true}
	}
	if r.ua != "" {
		req.Header.Set("User-Agent", r.ua)
	}
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	} else if r.body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if r.cook != "" {
		req.Header.Set("Cookie", r.cook)
	}
	req.RemoteAddr = "203.0.113.42:54321" // RFC 5737 TEST-NET

	parsed, perr := p.Parse(req)
	if perr != nil || parsed == nil {
		return evalResult{rec: r, parseErr: true}
	}
	_ = n.Normalize(parsed)
	ev := re.Evaluate(parsed)
	ids := make([]string, 0, len(ev.MatchedRules))
	for _, mr := range ev.MatchedRules {
		ids = append(ids, mr.RuleID)
	}
	return evalResult{rec: r, score: ev.TotalScore, matchedIDs: ids}
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

type confusion struct {
	TP, FP, TN, FN int
}

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
func (c confusion) accuracy() float64 {
	tot := c.TP + c.FP + c.TN + c.FN
	if tot == 0 {
		return 0
	}
	return float64(c.TP+c.TN) / float64(tot)
}
func (c confusion) balancedAcc() float64 {
	tnr := 0.0
	if c.FP+c.TN > 0 {
		tnr = float64(c.TN) / float64(c.FP+c.TN)
	}
	return (c.recall() + tnr) / 2
}

func confAt(results []evalResult, threshold float64) confusion {
	var c confusion
	for _, r := range results {
		if r.parseErr {
			continue
		}
		pos := r.score >= threshold
		attack := r.rec.label == "attack"
		switch {
		case attack && pos:
			c.TP++
		case attack && !pos:
			c.FN++
		case !attack && pos:
			c.FP++
		default:
			c.TN++
		}
	}
	return c
}

type opPoint struct {
	Name      string  `json:"name"`
	Threshold float64 `json:"threshold"`
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	TN        int     `json:"tn"`
	FN        int     `json:"fn"`
	Recall    float64 `json:"recall_tpr"`
	FPR       float64 `json:"fpr"`
	Precision float64 `json:"precision"`
	F1        float64 `json:"f1"`
	Accuracy  float64 `json:"accuracy"`
	BalAcc    float64 `json:"balanced_accuracy"`
}

func opOf(name string, t float64, results []evalResult) opPoint {
	c := confAt(results, t)
	return opPoint{
		Name: name, Threshold: t,
		TP: c.TP, FP: c.FP, TN: c.TN, FN: c.FN,
		Recall: c.recall(), FPR: c.fpr(), Precision: c.precision(),
		F1: c.f1(), Accuracy: c.accuracy(), BalAcc: c.balancedAcc(),
	}
}

type report struct {
	RulesFile      string             `json:"rules_file"`
	RulesLoaded    int                `json:"rules_loaded"`
	Split          string             `json:"split"`
	TotalEvaluated int                `json:"total_evaluated"`
	ParseErrors    int                `json:"parse_errors"`
	Attacks        int                `json:"attacks"`
	Benign         int                `json:"benign"`
	OperatingPts   []opPoint          `json:"operating_points"`
	InjectionOnly  []opPoint          `json:"operating_points_injection_subset"`
	PerCategory    map[string]catLine `json:"per_category"`
}

type catLine struct {
	Total        int     `json:"total"`
	BlockedGE5   int     `json:"blocked_ge5"`
	MonitoredGT0 int     `json:"monitored_gt0"`
	BlockRate    float64 `json:"block_rate"`
	MonitorRate  float64 `json:"monitor_rate"`
}

// ---------------------------------------------------------------------------

func main() {
	rulesPath := flag.String("rules", "configs/rules/all_rules.json", "rule file")
	split := flag.String("split", "test", "train | test | all")
	limit := flag.Int("limit", 0, "max records PER CLASS (0 = all)")
	tag := flag.String("tag", "", "output filename tag (default = split)")
	dataDir := flag.String("data", "eval/datasets/csic2010", "CSIC dataset dir")
	outDir := flag.String("out", "eval/results", "results output dir")
	exportPath := flag.String("export", "", "if set, write the evaluated records (with serve-accurate canonical ML text + proposed-system score) to this JSONL — the shared test set consumed by the CRS baseline and the ML OOD eval")
	flag.Parse()

	if *tag == "" {
		*tag = *split
	}

	re := engine.NewRuleEngine()
	re.SetThresholds(blockThreshold, 0.0)
	if err := re.LoadRulesFromFile(*rulesPath); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: load rules: %v\n", err)
		os.Exit(1)
	}
	nRules := re.RuleCount()
	p := parser.NewHTTPParser(10 << 20)
	n := normalizer.NewNormalizer()

	// Load corpus.
	benign, err := parseCSIC(*dataDir+"/normalTrafficTest.txt", "benign")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	attacks, err := parseCSIC(*dataDir+"/anomalousTrafficTest.txt", "attack")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}

	var corpus []record
	for _, r := range append(benign, attacks...) {
		r.split = splitOf(r)
		r.category = categorize(r)
		if *split != "all" && r.split != *split {
			continue
		}
		corpus = append(corpus, r)
	}

	// Per-class limit (deterministic — corpus is in file order).
	if *limit > 0 {
		var nb, na int
		var capped []record
		for _, r := range corpus {
			if r.label == "benign" && nb < *limit {
				capped = append(capped, r)
				nb++
			} else if r.label == "attack" && na < *limit {
				capped = append(capped, r)
				na++
			}
		}
		corpus = capped
	}

	// Evaluate.
	results := make([]evalResult, 0, len(corpus))
	for _, r := range corpus {
		results = append(results, scoreRecord(p, n, re, r))
	}

	// Aggregate.
	rep := report{
		RulesFile: *rulesPath, RulesLoaded: nRules, Split: *split,
		PerCategory: map[string]catLine{},
	}
	var injResults []evalResult
	for _, r := range results {
		if r.parseErr {
			rep.ParseErrors++
			continue
		}
		rep.TotalEvaluated++
		if r.rec.label == "attack" {
			rep.Attacks++
			if injectionClasses[r.rec.category] {
				injResults = append(injResults, r)
			}
		} else {
			rep.Benign++
			injResults = append(injResults, r) // benign counts toward FP in subset too
		}
		// per-category (attacks only)
		if r.rec.label == "attack" {
			cl := rep.PerCategory[r.rec.category]
			cl.Total++
			if r.score >= blockThreshold {
				cl.BlockedGE5++
			}
			if r.score > 0 {
				cl.MonitoredGT0++
			}
			rep.PerCategory[r.rec.category] = cl
		}
	}
	for k, cl := range rep.PerCategory {
		if cl.Total > 0 {
			cl.BlockRate = float64(cl.BlockedGE5) / float64(cl.Total)
			cl.MonitorRate = float64(cl.MonitoredGT0) / float64(cl.Total)
		}
		rep.PerCategory[k] = cl
	}

	rep.OperatingPts = []opPoint{
		opOf("BLOCK(>=5)", blockThreshold, results),
		opOf("MONITOR(>0)", monitorEpsilon, results),
	}
	rep.InjectionOnly = []opPoint{
		opOf("BLOCK(>=5)", blockThreshold, injResults),
		opOf("MONITOR(>0)", monitorEpsilon, injResults),
	}

	printReport(rep)
	writeArtifacts(*outDir, *tag, rep, results)

	if *exportPath != "" {
		if err := exportRecords(*exportPath, p, n, corpus, results); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: export failed: %v\n", err)
		} else {
			fmt.Printf("exported %d records -> %s\n", len(corpus), *exportPath)
		}
	}
}

// exportRecords writes one JSONL line per evaluated record so the CRS baseline
// and the ML OOD eval operate on the IDENTICAL test set (same split, same
// parsing) as the proposed system. Each line carries the raw request fields,
// the serve-accurate canonical ML text (exactly what middleware would send to
// the model), and the proposed system's score/verdict for side-by-side tables.
func exportRecords(path string, p *parser.HTTPParser, n *normalizer.Normalizer, corpus []record, results []evalResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i, r := range corpus {
		var req *http.Request
		var rerr error
		if r.body != "" {
			req, rerr = http.NewRequest(r.method, r.rawURL, strings.NewReader(r.body))
		} else {
			req, rerr = http.NewRequest(r.method, r.rawURL, nil)
		}
		if rerr != nil {
			continue
		}
		if r.ua != "" {
			req.Header.Set("User-Agent", r.ua)
		}
		if r.contentType != "" {
			req.Header.Set("Content-Type", r.contentType)
		} else if r.body != "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if r.cook != "" {
			req.Header.Set("Cookie", r.cook)
		}
		req.RemoteAddr = "203.0.113.42:54321"

		canon := ""
		if parsed, perr := p.Parse(req); perr == nil && parsed != nil {
			_ = n.Normalize(parsed)
			// Serve-accurate budget (ml.max_body_len) — NOT 256. A smaller cap
			// would truncate body-borne payloads off the end of the canonical
			// text and deflate the model's measured OOD recall.
			canon = training.BuildCanonicalText(parsed, nil, mlServeTextBudget)
		}
		score := 0.0
		if i < len(results) {
			score = results[i].score
		}
		line := map[string]any{
			"method":           r.method,
			"url":              r.rawURL,
			"body":             r.body,
			"user_agent":       r.ua,
			"cookie":           r.cook,
			"content_type":     r.contentType,
			"label":            r.label,    // "attack" | "benign"
			"category":         r.category, // sqli/xss/... or benign
			"proposed_score":   score,
			"proposed_blocked": score >= blockThreshold,
			"ml_text":          canon,
		}
		if err := enc.Encode(line); err != nil {
			return err
		}
	}
	return nil
}

func printReport(rep report) {
	line := strings.Repeat("=", 74)
	fmt.Println(line)
	fmt.Printf("WAF DETECTION BENCHMARK — CSIC 2010   (split=%s)\n", rep.Split)
	fmt.Printf("rules=%d  evaluated=%d  attacks=%d  benign=%d  parse_errors=%d\n",
		rep.RulesLoaded, rep.TotalEvaluated, rep.Attacks, rep.Benign, rep.ParseErrors)
	fmt.Println(line)

	pp := func(title string, ops []opPoint) {
		fmt.Printf("\n[%s]\n", title)
		fmt.Printf("  %-12s %6s %6s %6s %6s | %8s %7s %8s %6s %7s\n",
			"op", "TP", "FN", "FP", "TN", "Recall", "FPR", "Precis", "F1", "BalAcc")
		for _, o := range ops {
			fmt.Printf("  %-12s %6d %6d %6d %6d | %7.2f%% %6.2f%% %7.2f%% %6.3f %6.2f%%\n",
				o.Name, o.TP, o.FN, o.FP, o.TN,
				o.Recall*100, o.FPR*100, o.Precision*100, o.F1, o.BalAcc*100)
		}
	}
	pp("FULL anomalous set (incl. non-injection anomalies)", rep.OperatingPts)
	pp("INJECTION-CLASS subset (sqli/xss/traversal/rce/crlf/ssi_xxe)", rep.InjectionOnly)

	fmt.Printf("\n[PER ATTACK CATEGORY]\n")
	fmt.Printf("  %-16s %6s %10s %10s\n", "category", "total", "block>=5", "monitor>0")
	cats := make([]string, 0, len(rep.PerCategory))
	for k := range rep.PerCategory {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	for _, k := range cats {
		cl := rep.PerCategory[k]
		fmt.Printf("  %-16s %6d %9.1f%% %9.1f%%\n",
			k, cl.Total, cl.BlockRate*100, cl.MonitorRate*100)
	}
	fmt.Println()
}

func writeArtifacts(outDir, tag string, rep report, results []evalResult) {
	_ = os.MkdirAll(outDir, 0o755)

	// JSON metrics
	jb, _ := json.MarshalIndent(rep, "", "  ")
	_ = os.WriteFile(fmt.Sprintf("%s/run-%s.json", outDir, tag), jb, 0o644)

	// False negatives (attacks NOT blocked at >=5) — feeds the rule-author.
	// Injection-class first; sorted by score ascending (worst misses first).
	var fns []evalResult
	for _, r := range results {
		if !r.parseErr && r.rec.label == "attack" && r.score < blockThreshold {
			fns = append(fns, r)
		}
	}
	sort.SliceStable(fns, func(i, j int) bool {
		ii, jj := injectionClasses[fns[i].rec.category], injectionClasses[fns[j].rec.category]
		if ii != jj {
			return ii // injection-class first
		}
		return fns[i].score < fns[j].score
	})
	writeMissList(fmt.Sprintf("%s/false_negatives-%s.txt", outDir, tag), fns, rep)

	// False positives (benign blocked at >=5) — feeds the rule-author.
	var fps []evalResult
	for _, r := range results {
		if !r.parseErr && r.rec.label == "benign" && r.score >= blockThreshold {
			fps = append(fps, r)
		}
	}
	sort.SliceStable(fps, func(i, j int) bool { return fps[i].score > fps[j].score })
	writeFPList(fmt.Sprintf("%s/false_positives-%s.txt", outDir, tag), fps)
}

func writeMissList(path string, fns []evalResult, rep report) {
	var b strings.Builder
	fmt.Fprintf(&b, "# FALSE NEGATIVES — attacks NOT blocked (score < %.1f), split=%s\n", blockThreshold, rep.Split)
	fmt.Fprintf(&b, "# total missed: %d\n#\n", len(fns))
	hist := map[string]int{}
	for _, r := range fns {
		hist[r.rec.category]++
	}
	fmt.Fprintf(&b, "# missed by category (injection-class are the actionable ones):\n")
	cats := make([]string, 0, len(hist))
	for k := range hist {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	for _, k := range cats {
		flag := ""
		if injectionClasses[k] {
			flag = "  <-- actionable"
		}
		fmt.Fprintf(&b, "#   %-16s %5d%s\n", k, hist[k], flag)
	}
	b.WriteString("#\n# Each entry: score | category | METHOD url [| body]\n\n")
	for _, r := range fns {
		fmt.Fprintf(&b, "%.2f | %-13s | %s %s", r.score, r.rec.category, r.rec.method, r.rec.rawURL)
		if r.rec.body != "" {
			fmt.Fprintf(&b, " | BODY: %s", r.rec.body)
		}
		b.WriteByte('\n')
	}
	_ = os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeFPList(path string, fps []evalResult) {
	var b strings.Builder
	fmt.Fprintf(&b, "# FALSE POSITIVES — benign requests blocked (score >= %.1f)\n", blockThreshold)
	fmt.Fprintf(&b, "# total: %d\n", len(fps))
	b.WriteString("# Each entry: score | matched_rule_ids | METHOD url [| body]\n\n")
	for _, r := range fps {
		fmt.Fprintf(&b, "%.2f | %s | %s %s", r.score, strings.Join(r.matchedIDs, ","), r.rec.method, r.rec.rawURL)
		if r.rec.body != "" {
			fmt.Fprintf(&b, " | BODY: %s", r.rec.body)
		}
		b.WriteByte('\n')
	}
	_ = os.WriteFile(path, []byte(b.String()), 0o644)
}
