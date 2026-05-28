// internal/engine/tracker_persist.go
//
// Snapshot/Restore for the action.track counter store. Rules that use
// action.track lean on this counter to behave (e.g. "block IP after 5
// rapid auth failures"); a restart that wipes them effectively disables
// those rules until traffic rebuilds the counts.
//
// Expired entries are dropped on snapshot so we don't carry forward
// counters that were already about to vanish.
package engine

import (
	"encoding/json"
	"time"
)

type trackerSnapshotV1 struct {
	Version int                          `json:"version"`
	SavedAt time.Time                    `json:"saved_at"`
	Data    map[string]*trackEntryWire   `json:"data"`
}

type trackEntryWire struct {
	Count    int       `json:"count"`
	ExpireAt time.Time `json:"expire_at"`
}

// SnapshotState serializes every live counter for statestore. Already-
// expired entries are pruned so we never restore a counter that's about
// to be swept anyway. Name disambiguates from the existing Snapshot()
// diagnostic helper which returns a plain map for the dashboard.
func (t *Tracker) SnapshotState() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	snap := trackerSnapshotV1{
		Version: 1,
		SavedAt: now,
		Data:    make(map[string]*trackEntryWire, len(t.data)),
	}
	for k, e := range t.data {
		if now.After(e.expireAt) {
			continue
		}
		snap.Data[k] = &trackEntryWire{
			Count:    e.count,
			ExpireAt: e.expireAt,
		}
	}
	return json.Marshal(&snap)
}

// RestoreState loads counters. Entries whose expireAt is already past
// at restore time are silently dropped — a stale snapshot shouldn't
// resurrect counters the rule TTL would have killed.
func (t *Tracker) RestoreState(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var snap trackerSnapshotV1
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Version != 1 {
		return nil
	}

	now := time.Now()
	loaded := make(map[string]*trackEntry, len(snap.Data))
	for k, w := range snap.Data {
		if !now.Before(w.ExpireAt) {
			continue
		}
		loaded[k] = &trackEntry{
			count:    w.Count,
			expireAt: w.ExpireAt,
		}
	}
	t.mu.Lock()
	t.data = loaded
	t.mu.Unlock()
	return nil
}
