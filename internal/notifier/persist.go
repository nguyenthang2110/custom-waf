// internal/notifier/persist.go
//
// Snapshot/Restore for the notifier. Two surfaces are persisted:
//
//   1. State — dedup window, per-destination Sent/Failed/LastSentAt
//      counters and the lifetime atomic counters. Without this, every
//      restart clears dedup (causing duplicate alert spam for in-flight
//      attacks) and zeroes operational dashboards.
//
//   2. Destinations config — Slack/Email/Webhook destinations and their
//      enabled flags. The YAML file remains the bootstrap default;
//      runtime changes (dashboard add/remove/test) are persisted via
//      this surface so they survive restart.
//
// State and config are kept on separate statestore keys so an admin can
// wipe stats without losing destination definitions.
package notifier

import (
	"encoding/json"
	"time"
)

// =============================================================================
// State (dedup + counters)
// =============================================================================

type stateSnapshotV1 struct {
	Version int                  `json:"version"`
	SavedAt time.Time            `json:"saved_at"`
	Dedup   map[string]time.Time `json:"dedup"`
	Stats   statsWireV1          `json:"stats"`

	// Per-destination Stats keyed by destination ID. We persist by ID
	// (not by name) so destinations renamed at runtime keep their
	// counters.
	DestStats map[string]DestStats `json:"dest_stats"`
}

type statsWireV1 struct {
	Queued     uint64 `json:"queued"`
	Sent       uint64 `json:"sent"`
	Failed     uint64 `json:"failed"`
	Throttled  uint64 `json:"throttled"`
	BelowSev   uint64 `json:"below_severity"`
	SlackSent  uint64 `json:"slack_sent"`
	EmailSent  uint64 `json:"email_sent"`
	WebhookOK  uint64 `json:"webhook_ok"`
	LastError  string `json:"last_error,omitempty"`
	LastSentAt string `json:"last_sent_at,omitempty"`
}

// SnapshotState serializes dedup + stats. Destinations config is
// snapshotted separately via SnapshotDestinations so each can be
// wiped independently.
func (n *Notifier) SnapshotState() ([]byte, error) {
	if n == nil {
		return nil, nil
	}

	// Copy dedup under its own mutex.
	n.dedupMu.Lock()
	dedupCopy := make(map[string]time.Time, len(n.dedup))
	for k, v := range n.dedup {
		dedupCopy[k] = v
	}
	n.dedupMu.Unlock()

	// Copy per-destination stats by ID under the main mutex.
	n.mu.RLock()
	destStats := make(map[string]DestStats, len(n.cfg.Slack)+len(n.cfg.Email)+len(n.cfg.Webhook))
	for _, d := range n.cfg.Slack {
		if d.ID != "" {
			destStats[d.ID] = d.Stats
		}
	}
	for _, d := range n.cfg.Email {
		if d.ID != "" {
			destStats[d.ID] = d.Stats
		}
	}
	for _, d := range n.cfg.Webhook {
		if d.ID != "" {
			destStats[d.ID] = d.Stats
		}
	}
	n.mu.RUnlock()

	st := n.stats.snapshot()
	snap := stateSnapshotV1{
		Version:   1,
		SavedAt:   time.Now(),
		Dedup:     dedupCopy,
		DestStats: destStats,
		Stats: statsWireV1{
			Queued:     st.Queued,
			Sent:       st.Sent,
			Failed:     st.Failed,
			Throttled:  st.Throttled,
			BelowSev:   st.BelowSev,
			SlackSent:  st.SlackSent,
			EmailSent:  st.EmailSent,
			WebhookOK:  st.WebhookOK,
			LastError:  st.LastError,
			LastSentAt: st.LastSentAt,
		},
	}
	return json.Marshal(&snap)
}

// RestoreState loads dedup + stats. Per-destination counters are merged
// back into n.cfg by ID; destinations no longer present in the running
// config are dropped (their stats die with them, intentionally).
func (n *Notifier) RestoreState(data []byte) error {
	if n == nil || len(data) == 0 {
		return nil
	}
	var snap stateSnapshotV1
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Version != 1 {
		return nil
	}

	// Restore dedup map. Drop entries already older than the throttle
	// window — they won't suppress anything anyway and just bloat the
	// map.
	n.mu.RLock()
	window := time.Duration(n.cfg.ThrottleSeconds) * time.Second
	n.mu.RUnlock()
	now := time.Now()

	freshDedup := make(map[string]time.Time, len(snap.Dedup))
	for k, v := range snap.Dedup {
		if window > 0 && now.Sub(v) > window {
			continue
		}
		freshDedup[k] = v
	}
	n.dedupMu.Lock()
	n.dedup = freshDedup
	n.dedupMu.Unlock()

	// Restore atomic counters.
	n.stats.queued.Store(snap.Stats.Queued)
	n.stats.sent.Store(snap.Stats.Sent)
	n.stats.failed.Store(snap.Stats.Failed)
	n.stats.throttled.Store(snap.Stats.Throttled)
	n.stats.belowSev.Store(snap.Stats.BelowSev)
	n.stats.slackSent.Store(snap.Stats.SlackSent)
	n.stats.emailSent.Store(snap.Stats.EmailSent)
	n.stats.webhookOK.Store(snap.Stats.WebhookOK)
	if snap.Stats.LastError != "" {
		n.stats.lastErr.Store(snap.Stats.LastError)
	}
	if snap.Stats.LastSentAt != "" {
		n.stats.lastSentAt.Store(snap.Stats.LastSentAt)
	}

	// Merge per-destination stats into n.cfg by ID. We must rewrite
	// the destination slices because Stats lives inside each struct.
	n.mu.Lock()
	for i := range n.cfg.Slack {
		if s, ok := snap.DestStats[n.cfg.Slack[i].ID]; ok {
			n.cfg.Slack[i].Stats = s
		}
	}
	for i := range n.cfg.Email {
		if s, ok := snap.DestStats[n.cfg.Email[i].ID]; ok {
			n.cfg.Email[i].Stats = s
		}
	}
	for i := range n.cfg.Webhook {
		if s, ok := snap.DestStats[n.cfg.Webhook[i].ID]; ok {
			n.cfg.Webhook[i].Stats = s
		}
	}
	n.mu.Unlock()
	return nil
}

// =============================================================================
// Destinations config
//
// Persisting destinations means dashboard-added Slack/email/webhook
// hooks survive a restart. The YAML file is still the bootstrap default
// — on boot we restore the YAML config first, then layer the persisted
// destinations on top via SetConfig.
// =============================================================================

type destConfigSnapshotV1 struct {
	Version           int                  `json:"version"`
	SavedAt           time.Time            `json:"saved_at"`
	Enabled           bool                 `json:"enabled"`
	MinSeverity       string               `json:"min_severity"`
	ThrottleSeconds   int                  `json:"throttle_seconds"`
	SendRequestEvents bool                 `json:"send_request_events"`
	SendSystemEvents  bool                 `json:"send_system_events"`
	Slack             []SlackDestination   `json:"slack"`
	Email             []EmailDestination   `json:"email"`
	Webhook           []WebhookDestination `json:"webhook"`
}

// SnapshotDestinations serializes the destination config (Slack /
// Email / Webhook arrays plus the global Enabled / MinSeverity /
// ThrottleSeconds knobs). The Timeout is intentionally excluded — it
// follows the running binary, not the saved blob.
func (n *Notifier) SnapshotDestinations() ([]byte, error) {
	if n == nil {
		return nil, nil
	}
	n.mu.RLock()
	defer n.mu.RUnlock()

	// Copy the slices so the caller's mutation of the snapshot can't
	// race with live SetConfig.
	slackCopy := make([]SlackDestination, len(n.cfg.Slack))
	copy(slackCopy, n.cfg.Slack)
	emailCopy := make([]EmailDestination, len(n.cfg.Email))
	copy(emailCopy, n.cfg.Email)
	webhookCopy := make([]WebhookDestination, len(n.cfg.Webhook))
	copy(webhookCopy, n.cfg.Webhook)

	snap := destConfigSnapshotV1{
		Version:           1,
		SavedAt:           time.Now(),
		Enabled:           n.cfg.Enabled,
		MinSeverity:       n.cfg.MinSeverity,
		ThrottleSeconds:   n.cfg.ThrottleSeconds,
		SendRequestEvents: n.cfg.SendRequestEvents,
		SendSystemEvents:  n.cfg.SendSystemEvents,
		Slack:             slackCopy,
		Email:             emailCopy,
		Webhook:           webhookCopy,
	}
	return json.Marshal(&snap)
}

// RestoreDestinations replaces the destinations config with the
// persisted blob. The current SetConfig path is reused so all ID
// assignment / stats preservation invariants stay intact.
func (n *Notifier) RestoreDestinations(data []byte) error {
	if n == nil || len(data) == 0 {
		return nil
	}
	var snap destConfigSnapshotV1
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Version != 1 {
		return nil
	}
	n.mu.RLock()
	currentTimeout := n.cfg.Timeout
	n.mu.RUnlock()

	n.SetConfig(Config{
		Enabled:           snap.Enabled,
		MinSeverity:       snap.MinSeverity,
		ThrottleSeconds:   snap.ThrottleSeconds,
		SendRequestEvents: snap.SendRequestEvents,
		SendSystemEvents:  snap.SendSystemEvents,
		Timeout:           currentTimeout,
		Slack:             snap.Slack,
		Email:             snap.Email,
		Webhook:           snap.Webhook,
	})
	return nil
}

// =============================================================================
// statestore adapters
//
// statestore expects a single Snapshot/Restore interface per section,
// so we expose two thin wrappers — one for state, one for destinations.
// =============================================================================

// StateSnapshotter wraps SnapshotState/RestoreState for statestore.
type StateSnapshotter struct{ n *Notifier }

func (n *Notifier) StateSnapshotter() *StateSnapshotter { return &StateSnapshotter{n: n} }
func (s *StateSnapshotter) Snapshot() ([]byte, error)   { return s.n.SnapshotState() }
func (s *StateSnapshotter) Restore(data []byte) error   { return s.n.RestoreState(data) }

// DestSnapshotter wraps SnapshotDestinations/RestoreDestinations.
type DestSnapshotter struct{ n *Notifier }

func (n *Notifier) DestSnapshotter() *DestSnapshotter { return &DestSnapshotter{n: n} }
func (s *DestSnapshotter) Snapshot() ([]byte, error)  { return s.n.SnapshotDestinations() }
func (s *DestSnapshotter) Restore(data []byte) error  { return s.n.RestoreDestinations(data) }
