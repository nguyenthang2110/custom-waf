package ml

import (
	"testing"
	"time"
)

func TestCache_HitAndMiss(t *testing.T) {
	c := newPredictionCache(2, time.Minute)

	if _, ok := c.Get("a"); ok {
		t.Fatal("empty cache should miss")
	}
	c.Put("a", &PredictResponse{Label: "sqli"})
	got, ok := c.Get("a")
	if !ok || got.Label != "sqli" {
		t.Fatalf("expected hit, got ok=%v val=%v", ok, got)
	}
}

func TestCache_LRUEviction(t *testing.T) {
	c := newPredictionCache(2, time.Minute)
	c.Put("a", &PredictResponse{Label: "1"})
	c.Put("b", &PredictResponse{Label: "2"})
	// Touch a → b is now LRU.
	if _, ok := c.Get("a"); !ok {
		t.Fatal("expected hit on a")
	}
	c.Put("c", &PredictResponse{Label: "3"}) // evicts b

	if _, ok := c.Get("b"); ok {
		t.Error("b should have been evicted")
	}
	if _, ok := c.Get("a"); !ok {
		t.Error("a should still be present")
	}
	if _, ok := c.Get("c"); !ok {
		t.Error("c should be present")
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	c := newPredictionCache(2, 5*time.Millisecond)
	c.Put("a", &PredictResponse{Label: "x"})
	time.Sleep(15 * time.Millisecond)
	if _, ok := c.Get("a"); ok {
		t.Fatal("entry should have expired")
	}
}

func TestBreaker_TripsAfterThreshold(t *testing.T) {
	b := newCircuitBreaker(3, 50*time.Millisecond)

	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Fatalf("call %d blocked too early", i)
		}
		b.recordFailure()
	}
	if b.allow() {
		t.Fatal("breaker should be open after 3 failures")
	}

	// Cooldown elapses → half-open probe allowed.
	time.Sleep(60 * time.Millisecond)
	if !b.allow() {
		t.Fatal("expected half-open probe to be allowed")
	}
	// Subsequent call blocked while probe in flight.
	if b.allow() {
		t.Fatal("second concurrent call should be blocked in half-open")
	}
	b.recordSuccess()
	if !b.allow() {
		t.Fatal("breaker should be closed after probe success")
	}
}
