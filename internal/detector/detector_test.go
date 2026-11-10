package detector

import (
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
)

func TestSustainedRegressionAndRecovery(t *testing.T) {
	d := New(Options{BaselineSamples: 3, ConfirmSamples: 2, RecoverySamples: 2, Factor: 3})
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	observe := func(age float64, locks int) *Incident {
		at = at.Add(10 * time.Second)
		return d.Observe(collector.Snapshot{At: at, OldestQuerySeconds: age, LockWaiters: locks, BlockingGraph: &collector.BlockingGraph{Complete: true}})
	}
	for range 3 {
		if observe(0.2, 0) != nil {
			t.Fatal("alert during warmup")
		}
	}
	if observe(2, 1) != nil {
		t.Fatal("alert on transient spike")
	}
	started := at
	i := observe(4, 2)
	if i == nil || !i.StartedAt.Equal(started) || i.Finding != "lock_wait" || i.Trigger.Observed != 4 || i.Trigger.Threshold != 1 {
		t.Fatalf("unexpected investigation: %+v", i)
	}
	if observe(5, 2).Notify {
		t.Fatal("duplicate alert")
	}
	observe(0.2, 0)
	if resolved := observe(0.2, 0); resolved.Status != Resolved || !resolved.Notify {
		t.Fatalf("recovery was not confirmed: %+v", resolved)
	}
	observe(3, 0)
	i = observe(4, 0)
	if i == nil || i.Finding != "query_age_regression" {
		t.Fatalf("expected new episode without lock attribution: %+v", i)
	}
}

func TestIdleBaselineAndMissingData(t *testing.T) {
	d := New(Options{BaselineSamples: 3, ConfirmSamples: 1, RecoverySamples: 1, Factor: 3})
	for range 3 {
		d.Observe(collector.Snapshot{})
	}
	if d.Observe(collector.Snapshot{OldestQuerySeconds: 0.5}) != nil {
		t.Fatal("subsecond noise should not alert")
	}
	d.Missing(time.Now())
	for range 3 {
		if d.Observe(collector.Snapshot{OldestQuerySeconds: 2}) != nil {
			t.Fatal("reset must restart warmup")
		}
	}
	if d.Observe(collector.Snapshot{OldestQuerySeconds: 2}) != nil {
		t.Fatal("stable workload should not alert")
	}
}
