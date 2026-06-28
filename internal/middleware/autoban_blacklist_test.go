package middleware

import (
	"testing"
	"time"

	"waf-project/internal/behavior"
	"waf-project/internal/decision"
	"waf-project/internal/engine"
)

// helper: is ip present in the decision engine's access-control blacklist?
func blacklisted(de *decision.DecisionEngine, ip string) bool {
	for _, x := range de.GetBlacklistIPs() {
		if x == ip {
			return true
		}
	}
	return false
}

// TestAutoBanPromotesToBlacklist is the core guarantee the user asked for:
// once an IP trips the repeat-offender auto-ban, the WAF moves it into the
// access-control blacklist on its own, so every later request — even a clean
// one, even on a bypass path — is rejected until the ban expires.
//
// It drives the REAL behaviour detector and the REAL promotion helper the
// middleware calls (promoteBanToBlacklist); only the per-request loop that
// ServeHTTP would run is inlined.
func TestAutoBanPromotesToBlacklist(t *testing.T) {
	const ip = "198.51.100.7"

	det := behavior.NewDetector(behavior.BehaviorConfig{
		BruteForceThreshold: 3,               // ban after 3 blocked requests
		BruteForceWindow:    time.Minute,     // within this window
		BlockDuration:       time.Hour,       // stay banned this long
	})
	de := decision.NewDecisionEngine(decision.DecisionConfig{
		BlockThreshold:  5.0,
		EnableBlacklist: true,
	})

	// One "blocked attack" request from ip, mirroring the middleware order:
	// behaviour analysis → promote any fresh ban into the blacklist.
	fire := func() *behavior.BehaviorResult {
		ev := &engine.EvaluationResult{TotalScore: 6.0, Decision: "BLOCK"}
		req := &engine.ParsedRequest{ClientIP: ip, NormalizedPath: "/login"}
		br := det.Analyze(req, ev)
		promoteBanToBlacklist(de, br, time.Now())
		return br
	}

	// Below threshold: not banned, not blacklisted.
	for i := 1; i < 3; i++ {
		fire()
		if blacklisted(de, ip) {
			t.Fatalf("IP blacklisted too early after %d request(s)", i)
		}
	}

	// The 3rd blocked request trips the auto-ban → must land in the blacklist.
	br := fire()
	if br.BlockedUntil.IsZero() {
		t.Fatal("behaviour result has no BlockedUntil after hitting the threshold")
	}
	if !blacklisted(de, ip) {
		t.Fatalf("IP %s was auto-banned but NOT added to the access-control blacklist", ip)
	}

	// The promotion must make a *clean* request from that IP get blocked at the
	// blacklist gate — proving the ban now covers every path, not just attacks.
	clean := &engine.EvaluationResult{TotalScore: 0, Decision: "ALLOW"}
	req := &engine.ParsedRequest{ClientIP: ip, NormalizedPath: "/socket.io/"}
	benign := &behavior.BehaviorResult{ClientIP: ip, RecommendAction: "ALLOW"}
	res := de.DecideWithDetails(clean, req, benign)
	if res.Decision != "BLOCK" || !res.IsBlacklisted {
		t.Fatalf("clean request from banned IP not blocked via blacklist: decision=%s blacklisted=%v",
			res.Decision, res.IsBlacklisted)
	}
}

// TestPromoteBanToBlacklistGuards locks the promotion helper's contract so it
// never writes a bogus blacklist entry.
func TestPromoteBanToBlacklistGuards(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	mk := func() *decision.DecisionEngine {
		return decision.NewDecisionEngine(decision.DecisionConfig{EnableBlacklist: true})
	}

	t.Run("no ban → no entry", func(t *testing.T) {
		de := mk()
		br := &behavior.BehaviorResult{ClientIP: "1.1.1.1"} // BlockedUntil zero
		if promoteBanToBlacklist(de, br, now) {
			t.Error("promoted with zero BlockedUntil")
		}
		if len(de.GetBlacklistIPs()) != 0 {
			t.Error("blacklist not empty")
		}
	})

	t.Run("expired ban → no entry", func(t *testing.T) {
		de := mk()
		br := &behavior.BehaviorResult{ClientIP: "2.2.2.2", BlockedUntil: now.Add(-time.Minute)}
		if promoteBanToBlacklist(de, br, now) {
			t.Error("promoted with past BlockedUntil")
		}
	})

	t.Run("active ban → entry written", func(t *testing.T) {
		de := mk()
		br := &behavior.BehaviorResult{ClientIP: "3.3.3.3", BlockedUntil: now.Add(10 * time.Minute)}
		if !promoteBanToBlacklist(de, br, now) {
			t.Error("did not promote an active ban")
		}
		if !blacklisted(de, "3.3.3.3") {
			t.Error("active ban IP missing from blacklist")
		}
	})

	t.Run("nil-safe", func(t *testing.T) {
		if promoteBanToBlacklist(nil, nil, now) {
			t.Error("nil inputs should be a no-op")
		}
	})
}
