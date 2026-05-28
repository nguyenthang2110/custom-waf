package notifier

import (
	"testing"
)

func TestStateSnapshotRoundTrip(t *testing.T) {
	n := New(Config{
		Enabled:         true,
		MinSeverity:     "LOW",
		ThrottleSeconds: 300,
		Slack: []SlackDestination{
			{ID: "slack_1", Name: "ops", Enabled: true, WebhookURL: "https://example.com/slack"},
		},
	})
	defer n.Close()

	// Bump atomic counters and pretend one Slack send happened.
	n.stats.incQueued()
	n.stats.incQueued()
	n.stats.markSent()
	n.stats.incSlackSent()
	// Per-dest counters via internal helper:
	n.recordDestSend("slack_1", true, "")
	n.recordDestSend("slack_1", false, "boom")

	// Populate dedup so RestoreState can prove it round-trips.
	n.throttle(Event{ClientIP: "1.1.1.1", RuleID: "r1", Decision: "BLOCK"})

	blob, err := n.SnapshotState()
	if err != nil {
		t.Fatalf("SnapshotState: %v", err)
	}

	n2 := New(Config{
		Enabled:         true,
		MinSeverity:     "LOW",
		ThrottleSeconds: 300,
		Slack: []SlackDestination{
			{ID: "slack_1", Name: "ops", Enabled: true, WebhookURL: "https://example.com/slack"},
		},
	})
	defer n2.Close()
	if err := n2.RestoreState(blob); err != nil {
		t.Fatalf("RestoreState: %v", err)
	}

	st := n2.GetStats()
	if st.Queued != 2 {
		t.Errorf("Queued: got %d want 2", st.Queued)
	}
	if st.Sent != 1 {
		t.Errorf("Sent: got %d want 1", st.Sent)
	}
	if st.SlackSent != 1 {
		t.Errorf("SlackSent: got %d want 1", st.SlackSent)
	}

	cfg := n2.GetConfig()
	if len(cfg.Slack) != 1 || cfg.Slack[0].Stats.Sent != 1 || cfg.Slack[0].Stats.Failed != 1 {
		t.Errorf("per-dest stats lost: %+v", cfg.Slack[0].Stats)
	}

	// Dedup re-applied → repeat throttle on same key returns true.
	if !n2.throttle(Event{ClientIP: "1.1.1.1", RuleID: "r1", Decision: "BLOCK"}) {
		t.Errorf("dedup state lost — duplicate alert wouldn't be suppressed across restart")
	}
}

func TestDestSnapshotRoundTrip(t *testing.T) {
	n := New(Config{
		Enabled:         false, // start disabled, save enabled state
		MinSeverity:     "HIGH",
		ThrottleSeconds: 300,
	})
	defer n.Close()

	// Add a destination at runtime (mirroring dashboard add).
	n.SetConfig(Config{
		Enabled:         true,
		MinSeverity:     "LOW",
		ThrottleSeconds: 60,
		Slack: []SlackDestination{
			{Name: "incident-room", Enabled: true, WebhookURL: "https://hooks.slack.com/x"},
		},
		Webhook: []WebhookDestination{
			{Name: "siem", Enabled: true, URL: "https://siem.example.com/ingest", Method: "POST"},
		},
	})

	blob, err := n.SnapshotDestinations()
	if err != nil {
		t.Fatalf("SnapshotDestinations: %v", err)
	}

	// Fresh notifier with the YAML defaults — no destinations.
	n2 := New(Config{Enabled: false, MinSeverity: "HIGH", ThrottleSeconds: 300})
	defer n2.Close()
	if err := n2.RestoreDestinations(blob); err != nil {
		t.Fatalf("RestoreDestinations: %v", err)
	}

	cfg := n2.GetConfig()
	if !cfg.Enabled {
		t.Errorf("Enabled lost on restore")
	}
	if cfg.MinSeverity != "LOW" {
		t.Errorf("MinSeverity lost: %q", cfg.MinSeverity)
	}
	if len(cfg.Slack) != 1 || cfg.Slack[0].Name != "incident-room" {
		t.Errorf("Slack destination lost: %+v", cfg.Slack)
	}
	if len(cfg.Webhook) != 1 || cfg.Webhook[0].URL != "https://siem.example.com/ingest" {
		t.Errorf("Webhook destination lost: %+v", cfg.Webhook)
	}
}

func TestNotifierRestoreEmptyIsNoop(t *testing.T) {
	n := New(Config{Enabled: true})
	defer n.Close()
	if err := n.RestoreState(nil); err != nil {
		t.Fatal(err)
	}
	if err := n.RestoreDestinations(nil); err != nil {
		t.Fatal(err)
	}
}
