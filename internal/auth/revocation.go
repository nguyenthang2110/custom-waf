package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Revoker tracks JWT IDs (jti claim) that have been logged out before
// their `exp`. ValidateToken consults the revoker; logout adds to it.
// Empty interface so future implementations (Redis-backed, DB-backed)
// can drop in without changing handler code.
type Revoker interface {
	// Revoke marks jti as no-longer-valid until expiresAt. Calls with
	// jti=="" are no-ops so callers can pass a tokenless logout through.
	Revoke(jti string, expiresAt time.Time)
	// IsRevoked reports whether jti has been revoked.
	IsRevoked(jti string) bool
}

// MemoryRevoker is a single-instance in-memory blacklist with periodic
// expiry sweep. Good enough for a single WAF process; for HA you'd
// swap in a Redis-backed implementation.
//
// Memory growth is bounded: an entry stays only until its original
// `exp` passes, then the next sweep evicts it. Worst-case footprint =
// (logout rate) × (mean remaining token lifetime), which on a 24h JWT
// with even a generous 1 logout/s tops out at ~86k entries — trivial.
type MemoryRevoker struct {
	mu      sync.RWMutex
	entries map[string]time.Time // jti → expiry
	now     func() time.Time     // overridable for tests
}

// NewMemoryRevoker returns a Revoker and starts a background sweep
// goroutine. The returned cancel func stops the sweep — wire it to the
// process shutdown signal in main so tests don't leak goroutines.
func NewMemoryRevoker() (*MemoryRevoker, func()) {
	r := &MemoryRevoker{
		entries: make(map[string]time.Time),
		now:     time.Now,
	}
	stop := make(chan struct{})
	go r.sweepLoop(stop)
	return r, func() { close(stop) }
}

func (r *MemoryRevoker) Revoke(jti string, expiresAt time.Time) {
	if jti == "" {
		return
	}
	r.mu.Lock()
	r.entries[jti] = expiresAt
	r.mu.Unlock()
}

func (r *MemoryRevoker) IsRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	r.mu.RLock()
	exp, ok := r.entries[jti]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	// If the underlying expiry has already passed, the next sweep will
	// drop the entry — but in case a token somehow remains valid past
	// its expiry (clock skew), keep returning "revoked" until cleanup.
	return r.now().Before(exp.Add(time.Hour)) || exp.IsZero()
}

// sweepLoop evicts entries whose original `exp` is at least an hour in
// the past. The 1h grace window covers reasonable clock skew between
// the revoker's host and any downstream validator.
func (r *MemoryRevoker) sweepLoop(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			cutoff := r.now().Add(-1 * time.Hour)
			r.mu.Lock()
			for jti, exp := range r.entries {
				if exp.Before(cutoff) {
					delete(r.entries, jti)
				}
			}
			r.mu.Unlock()
		}
	}
}

// newJTI returns a 128-bit random hex string. Crypto-grade because a
// guessable jti would let an attacker poison the revocation set for
// another user's token. The standard library's crypto/rand is the only
// acceptable source.
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
