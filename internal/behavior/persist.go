// internal/behavior/persist.go
//
// Snapshot/Restore for the behavior detector. The detector's whole
// security value lives in its in-memory counters (failed attempts, bot
// flags, attack-category history per IP). Without persistence a restart
// resets every counter, letting attackers reset brute-force tries by
// coordinating WAF restarts.
//
// We serialize the three internal maps (ipStats, sessionStats,
// pathStats) as JSON. The struct fields are lowercase, so we mirror
// them in exported wire types here — that keeps the on-disk shape
// stable even if internal field names later get renamed.
package behavior

import (
	"encoding/json"
	"time"
)

// snapshotV1 is the serialized form of the detector. Fields are
// exported (capitalized) so encoding/json can see them. A `Version`
// field is included up-front so future migrations can branch cleanly.
type snapshotV1 struct {
	Version      int                          `json:"version"`
	SavedAt      time.Time                    `json:"saved_at"`
	IPStats      map[string]*ipStatsWire      `json:"ip_stats"`
	SessionStats map[string]*sessionStatsWire `json:"session_stats"`
	PathStats    map[string]*pathStatsWire    `json:"path_stats"`
}

type ipStatsWire struct {
	FailedAttempts     int            `json:"failed_attempts"`
	SuccessfulAttempts int            `json:"successful_attempts"`
	LastAttempt        time.Time      `json:"last_attempt"`
	FirstAttempt       time.Time      `json:"first_attempt"`
	IsBlocked          bool           `json:"is_blocked"`
	BlockedUntil       time.Time      `json:"blocked_until"`
	TotalRequests      int            `json:"total_requests"`
	UniquePaths        []string       `json:"unique_paths"`
	UniqueUserAgents   []string       `json:"unique_user_agents"`
	RequestTimestamps  []time.Time    `json:"request_timestamps"`
	SuspicionScore     float64        `json:"suspicion_score"`
	IsSuspicious       bool           `json:"is_suspicious"`
	IsBot              bool           `json:"is_bot"`
	DetectedAttacks    map[string]int `json:"detected_attacks"`
}

type sessionStatsWire struct {
	SessionID       string    `json:"session_id"`
	IPAddress       string    `json:"ip_address"`
	UserAgent       string    `json:"user_agent"`
	CreatedAt       time.Time `json:"created_at"`
	LastActivity    time.Time `json:"last_activity"`
	RequestCount    int       `json:"request_count"`
	FailedRequests  int       `json:"failed_requests"`
	BlockedRequests int       `json:"blocked_requests"`
}

type pathStatsWire struct {
	Path           string    `json:"path"`
	TotalAccess    int       `json:"total_access"`
	UniqueIPs      []string  `json:"unique_ips"`
	FailedAttempts int       `json:"failed_attempts"`
	LastAccess     time.Time `json:"last_access"`
}

// requestTimestampsCap bounds the per-IP timestamp slice on snapshot to
// avoid unbounded snapshot growth for long-lived noisy IPs. The
// velocity/bot checks only ever look at the last ~10 entries, so
// dropping older ones is safe.
const requestTimestampsCap = 256

// Snapshot serializes the detector's state to JSON. The mutex is held in
// read mode for the duration so concurrent Analyze() calls remain safe.
func (d *Detector) Snapshot() ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	snap := snapshotV1{
		Version:      1,
		SavedAt:      time.Now(),
		IPStats:      make(map[string]*ipStatsWire, len(d.ipStats)),
		SessionStats: make(map[string]*sessionStatsWire, len(d.sessionStats)),
		PathStats:    make(map[string]*pathStatsWire, len(d.pathStats)),
	}

	for ip, s := range d.ipStats {
		ts := s.requestTimestamps
		if len(ts) > requestTimestampsCap {
			ts = ts[len(ts)-requestTimestampsCap:]
		}
		// Copy the slice — the snapshot encoder must not see further
		// mutations after we drop the lock.
		tsCopy := make([]time.Time, len(ts))
		copy(tsCopy, ts)

		snap.IPStats[ip] = &ipStatsWire{
			FailedAttempts:     s.failedAttempts,
			SuccessfulAttempts: s.successfulAttempts,
			LastAttempt:        s.lastAttempt,
			FirstAttempt:       s.firstAttempt,
			IsBlocked:          s.isBlocked,
			BlockedUntil:       s.blockedUntil,
			TotalRequests:      s.totalRequests,
			UniquePaths:        keysOfBool(s.uniquePaths),
			UniqueUserAgents:   keysOfBool(s.uniqueUserAgents),
			RequestTimestamps:  tsCopy,
			SuspicionScore:     s.suspicionScore,
			IsSuspicious:       s.isSuspicious,
			IsBot:              s.isBot,
			DetectedAttacks:    copyIntMap(s.detectedAttacks),
		}
	}

	for sid, s := range d.sessionStats {
		snap.SessionStats[sid] = &sessionStatsWire{
			SessionID:       s.sessionID,
			IPAddress:       s.ipAddress,
			UserAgent:       s.userAgent,
			CreatedAt:       s.createdAt,
			LastActivity:    s.lastActivity,
			RequestCount:    s.requestCount,
			FailedRequests:  s.failedRequests,
			BlockedRequests: s.blockedRequests,
		}
	}

	for p, s := range d.pathStats {
		snap.PathStats[p] = &pathStatsWire{
			Path:           s.path,
			TotalAccess:    s.totalAccess,
			UniqueIPs:      keysOfBool(s.uniqueIPs),
			FailedAttempts: s.failedAttempts,
			LastAccess:     s.lastAccess,
		}
	}

	return json.Marshal(&snap)
}

// Restore overwrites the detector's state with the contents of data.
// Unknown / future versions are rejected so a stale snapshot doesn't
// silently zero out the fields the older code can't read.
func (d *Detector) Restore(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var snap snapshotV1
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Version != 1 {
		// Unknown — refuse to load. Caller logs and moves on; subsystem
		// retains its zero-value boot state.
		return nil
	}

	ipStats := make(map[string]*ipStatistics, len(snap.IPStats))
	for ip, w := range snap.IPStats {
		ts := make([]time.Time, len(w.RequestTimestamps))
		copy(ts, w.RequestTimestamps)
		ipStats[ip] = &ipStatistics{
			failedAttempts:     w.FailedAttempts,
			successfulAttempts: w.SuccessfulAttempts,
			lastAttempt:        w.LastAttempt,
			firstAttempt:       w.FirstAttempt,
			isBlocked:          w.IsBlocked,
			blockedUntil:       w.BlockedUntil,
			totalRequests:      w.TotalRequests,
			uniquePaths:        boolSetFromKeys(w.UniquePaths),
			uniqueUserAgents:   boolSetFromKeys(w.UniqueUserAgents),
			requestTimestamps:  ts,
			suspicionScore:     w.SuspicionScore,
			isSuspicious:       w.IsSuspicious,
			isBot:              w.IsBot,
			detectedAttacks:    copyIntMap(w.DetectedAttacks),
		}
	}

	sessionStats := make(map[string]*sessionStatistics, len(snap.SessionStats))
	for sid, w := range snap.SessionStats {
		sessionStats[sid] = &sessionStatistics{
			sessionID:       w.SessionID,
			ipAddress:       w.IPAddress,
			userAgent:       w.UserAgent,
			createdAt:       w.CreatedAt,
			lastActivity:    w.LastActivity,
			requestCount:    w.RequestCount,
			failedRequests:  w.FailedRequests,
			blockedRequests: w.BlockedRequests,
		}
	}

	pathStats := make(map[string]*pathStatistics, len(snap.PathStats))
	for p, w := range snap.PathStats {
		pathStats[p] = &pathStatistics{
			path:           w.Path,
			totalAccess:    w.TotalAccess,
			uniqueIPs:      boolSetFromKeys(w.UniqueIPs),
			failedAttempts: w.FailedAttempts,
			lastAccess:     w.LastAccess,
		}
	}

	d.mu.Lock()
	d.ipStats = ipStats
	d.sessionStats = sessionStats
	d.pathStats = pathStats
	d.mu.Unlock()

	return nil
}

func keysOfBool(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func boolSetFromKeys(keys []string) map[string]bool {
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out
}

func copyIntMap(m map[string]int) map[string]int {
	if len(m) == 0 {
		return make(map[string]int)
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
