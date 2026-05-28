// internal/metrics/persist.go
//
// Snapshot/Restore for the metrics collector. Persists the internal
// MetricsStats (totals, per-client counters, top rules / categories).
//
// Prometheus counters are deliberately NOT serialized — they live in
// the prometheus client and any reset on restart is expected by
// scrape-side tooling (which handles counter resets natively). What we
// persist is the dashboard's view of "since boot" which would otherwise
// reset every restart.
package metrics

import (
	"encoding/json"
	"time"
)

type snapshotV1 struct {
	Version         int                    `json:"version"`
	SavedAt         time.Time              `json:"saved_at"`
	StartTime       time.Time              `json:"start_time"`
	TotalRequests   int64                  `json:"total_requests"`
	TotalBlocked    int64                  `json:"total_blocked"`
	TotalChallenged int64                  `json:"total_challenged"`
	TotalAllowed    int64                  `json:"total_allowed"`
	TotalLatencyNs  int64                  `json:"total_latency_ns"`
	UniqueClients   int                    `json:"unique_clients"`
	TopRules        map[string]int64       `json:"top_rules"`
	TopCategories   map[string]int64       `json:"top_categories"`
	Clients         map[string]*clientWire `json:"clients"`
}

type clientWire struct {
	TotalRequests int64     `json:"total_requests"`
	TotalBlocked  int64     `json:"total_blocked"`
	LastSeen      time.Time `json:"last_seen"`
}

// Snapshot serializes MetricsStats.
func (c *Collector) Snapshot() ([]byte, error) {
	if c == nil || c.stats == nil {
		return nil, nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	clients := make(map[string]*clientWire, len(c.stats.Clients))
	for ip, s := range c.stats.Clients {
		if s == nil {
			continue
		}
		clients[ip] = &clientWire{
			TotalRequests: s.TotalRequests,
			TotalBlocked:  s.TotalBlocked,
			LastSeen:      s.LastSeen,
		}
	}

	return json.Marshal(&snapshotV1{
		Version:         1,
		SavedAt:         time.Now(),
		StartTime:       c.stats.StartTime,
		TotalRequests:   c.stats.TotalRequests,
		TotalBlocked:    c.stats.TotalBlocked,
		TotalChallenged: c.stats.TotalChallenged,
		TotalAllowed:    c.stats.TotalAllowed,
		TotalLatencyNs:  int64(c.stats.TotalLatency),
		UniqueClients:   c.stats.UniqueClients,
		TopRules:        copyMap(c.stats.TopRules),
		TopCategories:   copyMap(c.stats.TopCategories),
		Clients:         clients,
	})
}

// Restore replaces MetricsStats. StartTime is preserved from the
// snapshot — "uptime" then reflects the time since the metric
// collection started, not just since the current process started.
func (c *Collector) Restore(data []byte) error {
	if c == nil || len(data) == 0 {
		return nil
	}
	var snap snapshotV1
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Version != 1 {
		return nil
	}

	clients := make(map[string]*ClientStat, len(snap.Clients))
	for ip, w := range snap.Clients {
		if w == nil {
			continue
		}
		clients[ip] = &ClientStat{
			TotalRequests: w.TotalRequests,
			TotalBlocked:  w.TotalBlocked,
			LastSeen:      w.LastSeen,
		}
	}

	c.mu.Lock()
	c.stats.StartTime = snap.StartTime
	c.stats.TotalRequests = snap.TotalRequests
	c.stats.TotalBlocked = snap.TotalBlocked
	c.stats.TotalChallenged = snap.TotalChallenged
	c.stats.TotalAllowed = snap.TotalAllowed
	c.stats.TotalLatency = time.Duration(snap.TotalLatencyNs)
	c.stats.UniqueClients = snap.UniqueClients
	c.stats.TopRules = copyMap(snap.TopRules)
	c.stats.TopCategories = copyMap(snap.TopCategories)
	c.stats.Clients = clients
	c.mu.Unlock()
	return nil
}
