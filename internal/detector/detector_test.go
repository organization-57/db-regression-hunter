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
		return observeQuery(d, collector.Snapshot{At: at, OldestQuerySeconds: age, LockWaiters: locks, BlockingGraph: &collector.BlockingGraph{Complete: true}})
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
	if i == nil || !i.StartedAt.Equal(started) || !i.HasFinding(FindingLockWait) || i.Trigger.Observed != 4 || i.Trigger.Threshold != 1 {
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
	if i == nil || !i.HasFinding(FindingQueryAgeRegression) {
		t.Fatalf("expected new episode without lock attribution: %+v", i)
	}
}

func TestIdleBaselineAndMissingData(t *testing.T) {
	d := New(Options{BaselineSamples: 3, ConfirmSamples: 1, RecoverySamples: 1, Factor: 3})
	at := time.Now()
	for range 3 {
		at = at.Add(time.Second)
		observeQuery(d, collector.Snapshot{At: at})
	}
	if observeQuery(d, collector.Snapshot{At: at.Add(time.Second), OldestQuerySeconds: 0.5}) != nil {
		t.Fatal("subsecond noise should not alert")
	}
	d.Missing(at.Add(2 * time.Second))
	for range 3 {
		at = at.Add(time.Second)
		if observeQuery(d, collector.Snapshot{At: at, OldestQuerySeconds: 2}) != nil {
			t.Fatal("reset must restart warmup")
		}
	}
	at = at.Add(time.Second)
	if observeQuery(d, collector.Snapshot{At: at, OldestQuerySeconds: 2}) != nil {
		t.Fatal("stable workload should not alert")
	}
}

func incidentFor(updates []*Incident, metric string) *Incident {
	for _, i := range updates {
		if i.Trigger.Metric == metric {
			return i
		}
	}
	return nil
}
func observeQuery(d *Detector, s collector.Snapshot) *Incident {
	return incidentFor(d.Observe(s), "oldest_query_seconds")
}
