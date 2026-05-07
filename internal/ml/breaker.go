// internal/ml/breaker.go
//
// A minimal three-state circuit breaker used to short-circuit calls to the ML
// service after a streak of failures. Goal: stop hammering a sick downstream
// and let the WAF fall back to its rule-only decision quickly.
//
//	closed   → traffic flows; consecutive errors counted.
//	open     → calls fail fast with ErrCircuitOpen until cooldown elapses.
//	half-open→ one probe call is allowed; success closes, failure re-opens.
package ml

import (
	"fmt"
	"sync"
	"time"
)

// ErrCircuitOpen is returned by Predict when the breaker is open.
var ErrCircuitOpen = fmt.Errorf("ml: circuit breaker open")

type breakerState int

const (
	bsClosed breakerState = iota
	bsOpen
	bsHalfOpen
)

type circuitBreaker struct {
	mu sync.Mutex

	threshold int           // consecutive failures that trip the breaker
	cooldown  time.Duration // how long to stay open before half-open probe

	state    breakerState
	failures int
	openedAt time.Time
}

func newCircuitBreaker(threshold int, cooldown time.Duration) *circuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &circuitBreaker{
		threshold: threshold,
		cooldown:  cooldown,
		state:     bsClosed,
	}
}

// allow decides whether a new request may proceed. Must be paired with
// recordSuccess / recordFailure once the call resolves.
func (b *circuitBreaker) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case bsClosed:
		return true
	case bsOpen:
		if time.Since(b.openedAt) >= b.cooldown {
			// Cooldown elapsed → let one probe through.
			b.state = bsHalfOpen
			return true
		}
		return false
	case bsHalfOpen:
		// Only the first probe is allowed; while it's in flight, block others.
		return false
	}
	return true
}

func (b *circuitBreaker) recordSuccess() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.state = bsClosed
}

func (b *circuitBreaker) recordFailure() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures++
	if b.state == bsHalfOpen || b.failures >= b.threshold {
		b.state = bsOpen
		b.openedAt = time.Now()
	}
}

// State reports the current breaker state as a string for diagnostics.
func (b *circuitBreaker) State() string {
	if b == nil {
		return "disabled"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case bsClosed:
		return "closed"
	case bsOpen:
		return "open"
	case bsHalfOpen:
		return "half-open"
	}
	return "unknown"
}
