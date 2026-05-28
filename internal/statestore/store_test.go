package statestore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSnap is a minimal Snapshotter for unit testing the store
// orchestration code. It records how many times Snapshot/Restore were
// called and lets the test inject canned data.
type fakeSnap struct {
	mu        sync.Mutex
	snapData  []byte
	restoreFn func([]byte) error
	snapCnt   atomic.Int64
	restCnt   atomic.Int64
}

func (f *fakeSnap) Snapshot() ([]byte, error) {
	f.snapCnt.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapData, nil
}
func (f *fakeSnap) Restore(data []byte) error {
	f.restCnt.Add(1)
	if f.restoreFn != nil {
		return f.restoreFn(data)
	}
	return nil
}

// TestNilStoreNoops — every public method must accept a nil receiver.
// This lets callers stay branch-free when the DB is unreachable.
func TestNilStoreNoops(t *testing.T) {
	var s *Store
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("k", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if b, err := s.Load("k"); err != nil || b != nil {
		t.Fatalf("Load on nil: got (%v, %v)", b, err)
	}
	if err := s.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if got := s.RestoreAll(nil); got != 0 {
		t.Errorf("RestoreAll on nil: %d", got)
	}
	if got := s.SaveAll(nil); got != 0 {
		t.Errorf("SaveAll on nil: %d", got)
	}
}

// TestSnapshotterStartStop — a snapshotter with a nil store must still
// Start/Stop cleanly so callers don't have to branch.
func TestSnapshotterNilStoreStartStop(t *testing.T) {
	sn := NewSnapshotter(nil, nil, 30*time.Second)
	sn.Start()
	if err := sn.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

// TestSnapshotterIntervalClamp — values below 5s get bumped to 30s
// default to keep DB write rate sane.
func TestSnapshotterIntervalClamp(t *testing.T) {
	sn := NewSnapshotter(nil, nil, 100*time.Millisecond)
	if sn.interval != 30*time.Second {
		t.Errorf("interval: got %v want 30s (clamped)", sn.interval)
	}
}
