package sqlstats

import (
	"math"
	"testing"
	"time"
)

func fixture() Snapshot {
	at := time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)
	return Snapshot{At: at, Available: true, ServerStartedAt: at.Add(-time.Hour), ResetAt: at.Add(-time.Minute), Entries: []Counters{{
		Identity: Identity{DatabaseID: 1, UserID: 2, QueryID: "9223372036854775806", TopLevel: true}, Since: at.Add(-time.Minute),
		Calls: 100, TotalExecMS: 1000, SharedReads: 40, SharedHits: 200, TempReads: 10, TempWrites: 20, Rows: 100,
	}}}
}

func next(s Snapshot) Snapshot {
	s.At = s.At.Add(10 * time.Second)
	s.Entries = append([]Counters(nil), s.Entries...)
	return s
}

func TestIntervalUsesDeltasAndDistinguishesLoadFromExecutionCost(t *testing.T) {
	tracker := &Tracker{}
	first := fixture()
	if r := tracker.Observe(first); r.Status != "warming_up" || len(r.Queries) != 0 {
		t.Fatal(r)
	}
	second := next(first)
	c := &second.Entries[0]
	c.Calls += 10
	c.TotalExecMS += 200
	c.SharedReads += 30
	c.SharedHits += 40
	c.TempReads += 5
	c.TempWrites += 20
	c.Rows += 50
	r := tracker.Observe(second)
	if r.Status != "ready" || len(r.Queries) != 1 || r.IntervalSeconds != 10 {
		t.Fatalf("bad interval: %+v", r)
	}
	q := r.Queries[0]
	if q.Calls != 10 || q.CallsPerSecond != 1 || q.MeanExecMS != 20 || q.SharedReadsPerCall != 3 || q.SharedHitsPerCall != 4 || q.TempReadsPerCall != .5 || q.TempWritesPerCall != 2 || q.RowsPerCall != 5 {
		t.Fatalf("bad deltas: %+v", q)
	}
	third := next(second)
	third.Entries[0].Calls += 20
	third.Entries[0].TotalExecMS += 400
	r = tracker.Observe(third)
	if r.Queries[0].MeanExecMS != 20 || r.Queries[0].CallsPerSecond != 2 {
		t.Fatal("higher traffic was confused with slower executions", r)
	}
}

func TestInvalidIntervalsRewarmInsteadOfCreatingSpikes(t *testing.T) {
	for _, kind := range []string{"global_reset", "restart", "eviction", "gap", "unavailable"} {
		t.Run(kind, func(t *testing.T) {
			first := fixture()
			tracker := &Tracker{MaxSampleGap: 30 * time.Second}
			tracker.Observe(first)
			second := next(first)
			second.Entries[0].Calls += 100
			second.Entries[0].TotalExecMS += 100000
			want := "reset"
			switch kind {
			case "global_reset":
				second.ResetAt = second.At
			case "restart":
				second.ServerStartedAt = second.At
			case "eviction":
				second.Deallocations++
			case "gap":
				second.At = first.At.Add(time.Minute)
				want = "gap"
			case "unavailable":
				second.Available = false
				second.Reason = "collection_failed"
				want = "unavailable"
			}
			r := tracker.Observe(second)
			if r.Status != want || len(r.Queries) != 0 {
				t.Fatalf("invalid delta escaped: %+v", r)
			}
			third := next(second)
			third.Available = true
			if kind == "unavailable" {
				if r = tracker.Observe(third); r.Status != "warming_up" {
					t.Fatal("bridged failed collection", r)
				}
				third = next(third)
			}
			third.Entries[0].Calls++
			third.Entries[0].TotalExecMS += 5
			r = tracker.Observe(third)
			if r.Status != "ready" || len(r.Queries) != 1 || r.Queries[0].Calls != 1 || r.Queries[0].MeanExecMS != 5 {
				t.Fatalf("did not resume with a fresh interval: %+v", r)
			}
		})
	}
}

func TestEntryResetNewMissingAndIdle(t *testing.T) {
	for _, kind := range []string{"since", "calls", "time", "reads", "nan", "infinity"} {
		t.Run(kind, func(t *testing.T) {
			first := fixture()
			second := next(first)
			tracker := &Tracker{}
			tracker.Observe(first)
			second.Entries[0].Calls += 10
			second.Entries[0].TotalExecMS += 10
			switch kind {
			case "since":
				second.Entries[0].Since = second.At // Counts can exceed their pre-reset values.
			case "calls":
				second.Entries[0].Calls = 0
			case "time":
				second.Entries[0].TotalExecMS = 0
			case "reads":
				second.Entries[0].SharedReads = 0
			case "nan":
				second.Entries[0].TotalExecMS = math.NaN()
			case "infinity":
				second.Entries[0].TotalExecMS = math.Inf(1)
			}
			r := tracker.Observe(second)
			if r.ResetStatements != 1 || len(r.Queries) != 0 {
				t.Fatalf("reset produced a rate: %+v", r)
			}
		})
	}
	tracker := &Tracker{}
	first := fixture()
	tracker.Observe(first)
	idle := next(first)
	if r := tracker.Observe(idle); r.Status != "ready" || r.ActiveStatements != 0 || len(r.Queries) != 0 {
		t.Fatal("zero calls should not divide by zero", r)
	}
	missing := next(idle)
	missing.Entries = nil
	if r := tracker.Observe(missing); r.MissingStatements != 1 {
		t.Fatal(r)
	}
	reappeared := next(missing)
	reappeared.Entries = first.Entries
	if r := tracker.Observe(reappeared); r.NewStatements != 1 || len(r.Queries) != 0 {
		t.Fatal("reappearing entry reused an old baseline", r)
	}
}

func TestIdentityPrecisionOwnershipAndTimestampOrder(t *testing.T) {
	first := fixture()
	tracker := &Tracker{}
	tracker.Observe(first)
	// The producer can reuse its buffers after Observe returns.
	first.Entries[0].Calls = 0
	old := fixture()
	old.At = old.At.Add(-time.Second)
	if r := tracker.Observe(old); r.Status != "stale" {
		t.Fatal(r)
	}
	second := next(fixture())
	second.Entries[0].Calls += 2
	second.Entries[0].TotalExecMS += 20
	// Same queryid under another role is a separate first-seen entry.
	other := second.Entries[0]
	other.UserID++
	second.Entries = append(second.Entries, other)
	r := tracker.Observe(second)
	if r.NewStatements != 1 || len(r.Queries) != 1 || r.Queries[0].Calls != 2 || r.Queries[0].QueryID != "9223372036854775806" {
		t.Fatalf("identity or baseline corrupted: %+v", r)
	}
}
