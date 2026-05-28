package notifier

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestWebhookDispatchAndThrottle verifies:
//   1. enabled webhook destination receives the JSON event,
//   2. severity filter drops low-severity events,
//   3. dedup throttle suppresses duplicates inside the window,
//   4. multi-destination fanout — two webhooks both fire.
func TestWebhookDispatchAndThrottle(t *testing.T) {
	var hits1, hits2 atomic.Int32
	last := make(chan map[string]interface{}, 4)

	mk := func(c *atomic.Int32) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Add(1)
			body, _ := io.ReadAll(r.Body)
			var m map[string]interface{}
			_ = json.Unmarshal(body, &m)
			select {
			case last <- m:
			default:
			}
			w.WriteHeader(200)
		}))
	}
	srv1 := mk(&hits1)
	srv2 := mk(&hits2)
	defer srv1.Close()
	defer srv2.Close()

	n := New(Config{
		Enabled:         true,
		MinSeverity:     "HIGH",
		ThrottleSeconds: 60,
		Webhook: []WebhookDestination{
			{ID: "wh1", Name: "primary", Enabled: true, URL: srv1.URL, Method: "POST"},
			{ID: "wh2", Name: "audit",   Enabled: true, URL: srv2.URL, Method: "POST"},
		},
	})
	defer n.Close()

	// Below severity (MEDIUM) — dropped pre-queue.
	n.Send(Event{Severity: "MEDIUM", ClientIP: "1.1.1.1", Decision: "BLOCK", RuleID: "R1"})

	// HIGH → delivered to BOTH destinations.
	n.Send(Event{Severity: "HIGH", ClientIP: "1.1.1.1", Decision: "BLOCK", RuleID: "R1"})
	// Duplicate (same ip|rule|decision) → throttled (no fanout).
	n.Send(Event{Severity: "HIGH", ClientIP: "1.1.1.1", Decision: "BLOCK", RuleID: "R1"})
	// Different IP → delivered to both.
	n.Send(Event{Severity: "CRITICAL", ClientIP: "2.2.2.2", Decision: "BLOCK", RuleID: "R1"})

	deadline := time.After(3 * time.Second)
	for hits1.Load() < 2 || hits2.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("expected ≥2 hits each, got %d / %d (stats=%+v)", hits1.Load(), hits2.Load(), n.GetStats())
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}

	stats := n.GetStats()
	if stats.WebhookOK < 4 { // 2 events × 2 destinations
		t.Fatalf("expected webhook_sent ≥ 4, got %+v", stats)
	}
	if stats.BelowSev < 1 {
		t.Fatalf("expected below_severity ≥ 1, got %+v", stats)
	}
	if stats.Throttled < 1 {
		t.Fatalf("expected throttled ≥ 1, got %+v", stats)
	}

	// Sample one received body for shape validation.
	select {
	case got := <-last:
		if !strings.EqualFold(got["decision"].(string), "BLOCK") {
			t.Fatalf("bad decision in body: %v", got)
		}
	default:
		t.Fatal("no body captured")
	}

	// Per-destination Stats should be populated.
	live := n.GetConfig()
	for _, d := range live.Webhook {
		if d.Stats.Sent < 2 {
			t.Fatalf("dest %s expected Sent≥2, got %+v", d.ID, d.Stats)
		}
	}
}

// TestTemplateRendering verifies {placeholder} substitution + webhook
// content-type fallback to text/plain when the rendered body isn't JSON.
func TestTemplateRendering(t *testing.T) {
	var ct, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	n := New(Config{
		Enabled:     true,
		MinSeverity: "INFO",
	})
	defer n.Close()

	res := n.TestWebhook(WebhookDestination{
		ID:              "wh-tpl",
		Enabled:         true,
		URL:             srv.URL,
		PayloadTemplate: "Plain alert: {severity} on {path} ({client_ip})",
		Headers:         map[string]string{"X-Tenant": "prod"},
	})
	if res != "OK" {
		t.Fatalf("test returned %q", res)
	}
	if !strings.Contains(body, "Plain alert: HIGH on /__test (127.0.0.1)") {
		t.Fatalf("template not rendered: got %q", body)
	}
	if !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("expected text/plain for non-JSON body, got %q", ct)
	}
}

// TestPerDestinationTestBypassesFilter confirms TestWebhook ignores global
// MinSeverity and Enabled flags — used by the dashboard test button.
func TestPerDestinationTestBypassesFilter(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(204)
	}))
	defer srv.Close()

	n := New(Config{
		Enabled:     false, // global off
		MinSeverity: "CRITICAL",
	})
	defer n.Close()

	if r := n.TestWebhook(WebhookDestination{ID: "x", URL: srv.URL}); r != "OK" {
		t.Fatalf("expected OK, got %q", r)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 hit, got %d", hits.Load())
	}
}

// TestAutoAssignID verifies SetConfig fills in missing destination IDs and
// keeps existing ones stable across saves.
func TestAutoAssignID(t *testing.T) {
	n := New(Config{Enabled: false})
	defer n.Close()

	n.SetConfig(Config{
		Slack: []SlackDestination{
			{Name: "A", WebhookURL: "https://example.com/a"}, // no ID
			{ID: "slack_keep", Name: "B", WebhookURL: "https://example.com/b"},
		},
	})
	got := n.GetConfig()
	if len(got.Slack) != 2 {
		t.Fatalf("expected 2 slack dests, got %d", len(got.Slack))
	}
	if got.Slack[0].ID == "" {
		t.Fatalf("first destination should have an auto-assigned ID")
	}
	if got.Slack[1].ID != "slack_keep" {
		t.Fatalf("second destination should keep ID, got %q", got.Slack[1].ID)
	}
}
