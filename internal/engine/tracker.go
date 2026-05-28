// internal/engine/tracker.go
//
// In-memory counter store used by action.track. Keyed by (scope, counter, identity).
//   - scope: "ip" | "session" | "global"
//   - counter: free-form per-rule label (defaults to rule ID)
//   - identity: client IP / session ID / "" for global
//
// Counters auto-expire after TTL; a background sweeper releases old keys.
package engine

import (
	"sync"
	"time"
)

// Tracker — concurrent in-memory counter map.
type Tracker struct {
	mu       sync.Mutex
	data     map[string]*trackEntry
	stopCh   chan struct{}
	started  bool
}

type trackEntry struct {
	count    int
	expireAt time.Time
}

// NewTracker creates a tracker and starts its background sweeper.
func NewTracker() *Tracker {
	t := &Tracker{
		data:   make(map[string]*trackEntry),
		stopCh: make(chan struct{}),
	}
	t.start()
	return t
}

func (t *Tracker) start() {
	if t.started {
		return
	}
	t.started = true
	go func() {
		tick := time.NewTicker(1 * time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-t.stopCh:
				return
			case <-tick.C:
				t.sweep()
			}
		}
	}()
}

// Stop terminates the background sweeper. Safe to call multiple times.
func (t *Tracker) Stop() {
	if !t.started {
		return
	}
	select {
	case <-t.stopCh:
		// already closed
	default:
		close(t.stopCh)
	}
	t.started = false
}

// Incr increments the counter and returns the new value. ttl defines the
// inactivity window; each increment refreshes the expiry.
func (t *Tracker) Incr(key string, ttl time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	e, ok := t.data[key]
	if !ok || now.After(e.expireAt) {
		e = &trackEntry{count: 0, expireAt: now.Add(ttl)}
		t.data[key] = e
	}
	e.count++
	e.expireAt = now.Add(ttl)
	return e.count
}

// Get returns the current counter (0 if absent/expired).
func (t *Tracker) Get(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.data[key]
	if !ok || time.Now().After(e.expireAt) {
		return 0
	}
	return e.count
}

// Reset clears one counter.
func (t *Tracker) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.data, key)
}

// Snapshot returns all live counters (for diagnostics / API).
func (t *Tracker) Snapshot() map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]int, len(t.data))
	now := time.Now()
	for k, e := range t.data {
		if now.Before(e.expireAt) {
			out[k] = e.count
		}
	}
	return out
}

func (t *Tracker) sweep() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for k, e := range t.data {
		if now.After(e.expireAt) {
			delete(t.data, k)
		}
	}
}

// =========================================================================
// Key composition
// =========================================================================

func trackKey(scope, counter, identity string) string {
	return scope + ":" + counter + ":" + identity
}

func resolveIdentity(scope string, req *ParsedRequest) string {
	switch scope {
	case "ip":
		return req.ClientIP
	case "session":
		// Heuristic: prefer common session cookie names, fallback to UA hash.
		for _, name := range []string{"sessionid", "PHPSESSID", "JSESSIONID", "session"} {
			if v, ok := req.Cookies[name]; ok && v != "" {
				return v
			}
		}
		return req.ClientIP + "|" + req.UserAgent
	case "global":
		return ""
	}
	return req.ClientIP
}
