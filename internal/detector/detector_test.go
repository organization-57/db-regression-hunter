package detector

import (
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
)

func TestSustainedRegressionAndRecovery(t *testing.T) {
	d := New(3, 2, 3)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	observe := func(age float64, locks int) *Incident {
		at = at.Add(10 * time.Second)
		return d.Observe(collector.Snapshot{At: at, OldestQuerySeconds: age, LockWaiters: locks})
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
	if i == nil || !i.StartedAt.Equal(started) || len(i.Evidence) != 2 || i.Hypothesis != "Блокировки — возможная причина деградации" {
		t.Fatalf("unexpected investigation: %+v", i)
	}
	if observe(5, 2) != nil {
		t.Fatal("duplicate alert")
	}
	observe(0.2, 0)
	observe(3, 0)
	i = observe(4, 0)
	if i == nil || i.Hypothesis != "Причина пока не установлена: вырос возраст активных запросов" {
		t.Fatalf("expected new episode without lock attribution: %+v", i)
	}
}

func TestIdleBaselineAndReset(t *testing.T) {
	d := New(3, 1, 3)
	for range 3 {
		d.Observe(collector.Snapshot{})
	}
	if d.Observe(collector.Snapshot{OldestQuerySeconds: 0.5}) != nil {
		t.Fatal("subsecond noise should not alert")
	}
	if d.Observe(collector.Snapshot{OldestQuerySeconds: 2}) == nil {
		t.Fatal("expected regression")
	}
	d.Reset()
	for range 3 {
		if d.Observe(collector.Snapshot{OldestQuerySeconds: 2}) != nil {
			t.Fatal("reset must restart warmup")
		}
	}
	if d.Observe(collector.Snapshot{OldestQuerySeconds: 2}) != nil {
		t.Fatal("stable workload should not alert")
	}
}
