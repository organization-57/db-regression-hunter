package sqlstats

import (
	"fmt"
	"testing"
	"time"
)

type regressionFixture struct {
	tracker *Tracker
	sample  Snapshot
}

func newRegressionFixture() *regressionFixture {
	s := fixture()
	t := &Tracker{MaxSampleGap: 30 * time.Second, Regressor: NewRegressor(3, 2, 3, 5, 5)}
	t.Observe(s)
	return &regressionFixture{tracker: t, sample: s}
}
func (f *regressionFixture) observe(calls int64, ms float64) Report {
	f.sample = next(f.sample)
	f.sample.Entries[0].Calls += calls
	f.sample.Entries[0].TotalExecMS += float64(calls) * ms
	return f.tracker.Observe(f.sample)
}
func (f *regressionFixture) warm() {
	for range 3 {
		f.observe(10, 1)
	}
}

func TestSQLRegressionConfirmationFrozenBaselineAndRecovery(t *testing.T) {
	f := newRegressionFixture()
	f.warm()
	pending := f.observe(10, 10)
	if pending.PendingRegressions != 1 || pending.ActiveRegressions != 0 || pending.Top[0].Comparison.BaselineMeanExecMS != 1 {
		t.Fatalf("missing first suspicion: %+v", pending)
	}
	opened := f.observe(10, 20)
	if opened.ActiveRegressions != 1 || len(opened.Regressions) != 1 || opened.Top[0].Comparison.BaselineMeanExecMS != 1 || opened.Top[0].Comparison.ThresholdMS != 6 {
		t.Fatalf("missing regression: %+v", opened)
	}
	episode := opened.Regressions[0]
	if !episode.StartedAt.Equal(pending.From) || !episode.DetectedAt.Equal(opened.At) || episode.Current.Comparison.Confirmations != 2 {
		t.Fatal("incorrect onset/confirmation", episode)
	}
	again := f.observe(10, 30)
	if again.Regressions[0].DetectedAt != episode.DetectedAt || again.Top[0].Comparison.BaselineMeanExecMS != 1 {
		t.Fatal("episode duplicated or baseline contaminated", again)
	}
	recovering := f.observe(10, 1)
	if recovering.ActiveRegressions != 1 || recovering.RecoveringRegressions != 1 || recovering.ResolvedRegressions != 0 {
		t.Fatal("one normal interval resolved regression", recovering)
	}
	relapse := f.observe(10, 10)
	if relapse.RecoveringRegressions != 0 || relapse.ActiveRegressions != 1 {
		t.Fatal("relapse did not reset recovery", relapse)
	}
	f.observe(10, 1)
	resolved := f.observe(10, 1)
	if resolved.ActiveRegressions != 0 || resolved.UnknownRegressions != 0 || resolved.ResolvedRegressions != 1 || resolved.Regressions[0].RecoveredAt == nil {
		t.Fatalf("missing confirmed recovery: %+v", resolved)
	}
	if episode.Status != "active" || episode.Current.Comparison.RecoverySamples != 0 {
		t.Fatal("later interval mutated emitted evidence")
	}
	f.observe(10, 10)
	reopened := f.observe(10, 10)
	if reopened.ActiveRegressions != 1 || reopened.Regressions[0].DetectedAt == episode.DetectedAt {
		t.Fatal("new episode did not reopen", reopened)
	}
}

func TestSQLTrafficGrowthIsSeparateFromSlowExecution(t *testing.T) {
	f := newRegressionFixture()
	f.warm()
	for range 5 {
		r := f.observe(100, 1)
		if r.ActiveRegressions != 0 || r.PendingRegressions != 0 || r.Top[0].Comparison.ExecFactor == nil || *r.Top[0].Comparison.ExecFactor != 1 {
			t.Fatal("load growth triggered slowdown", r)
		}
	}
	f = newRegressionFixture()
	f.warm()
	r := f.observe(100, 10)
	if !r.Top[0].Comparison.LoadIncreased || r.Top[0].Comparison.CallRateFactor == nil || *r.Top[0].Comparison.CallRateFactor != 10 {
		t.Fatal("lost simultaneous load growth", r)
	}
	r = f.observe(100, 10)
	if r.ActiveRegressions != 1 || !r.Regressions[0].Current.Comparison.LoadIncreased {
		t.Fatal("load growth concealed execution slowdown", r)
	}
}

func TestSQLUsesWeightedReferenceAndAbsoluteNoiseFloor(t *testing.T) {
	f := newRegressionFixture()
	f.observe(10, 1)
	f.observe(100, 2)
	f.observe(10, 1)
	r := f.observe(10, 3)
	if c := r.Top[0].Comparison; c.BaselineCalls != 120 || c.BaselineMeanExecMS != 220.0/120 || c.State != "normal" {
		t.Fatal("baseline is not weighted by executions", r)
	}
	f = newRegressionFixture()
	for range 3 {
		f.observe(10, .01)
	}
	for range 3 {
		r = f.observe(10, .05)
		if r.PendingRegressions != 0 || r.ActiveRegressions != 0 {
			t.Fatal("tiny absolute change generated alert", r)
		}
	}
}

func TestSQLInsufficientCallsAndIdleNeverConfirmOrResolve(t *testing.T) {
	f := newRegressionFixture()
	for range 5 {
		r := f.observe(1, 100)
		if r.BaselinedStatements != 0 || r.Top[0].Comparison.State != "insufficient_calls" {
			t.Fatal("rare calls built a reference", r)
		}
	}
	f.warm()
	f.observe(10, 10)
	rare := f.observe(1, 100)
	if rare.PendingRegressions != 0 {
		t.Fatal("rare interval extended streak", rare)
	}
	if r := f.observe(10, 10); r.ActiveRegressions != 0 || r.PendingRegressions != 1 {
		t.Fatal("confirmation bridged low-volume interval", r)
	}
	f.observe(10, 10)
	f.observe(10, 1)
	idle := f.observe(0, 0)
	if idle.UnknownRegressions != 1 || idle.ResolvedRegressions != 0 || idle.Regressions[0].Reason != "insufficient_calls" {
		t.Fatal("no calls falsely proved recovery", idle)
	}
	rare = f.observe(1, 1)
	if rare.UnknownRegressions != 1 || rare.Regressions[0].Current.Comparison.State != "insufficient_calls" {
		t.Fatal(rare)
	}
	if r := f.observe(10, 1); r.RecoveringRegressions != 1 || r.ResolvedRegressions != 0 {
		t.Fatal("recovery bridged insufficient data", r)
	}
	if r := f.observe(10, 1); r.ResolvedRegressions != 1 {
		t.Fatal(r)
	}
}

func TestSQLInterruptionsPreserveOpenEpisodeWithoutFalseRecovery(t *testing.T) {
	for _, kind := range []string{"unavailable", "reset", "gap", "partial_reset", "missing", "explicit_failure"} {
		t.Run(kind, func(t *testing.T) {
			f := newRegressionFixture()
			f.warm()
			f.observe(10, 10)
			open := f.observe(10, 10)
			f.observe(10, 1)
			f.sample = next(f.sample)
			switch kind {
			case "unavailable":
				f.sample.Available = false
				f.sample.Reason = "collection_failed"
			case "reset":
				f.sample.ResetAt = f.sample.At
			case "gap":
				f.sample.At = f.sample.At.Add(time.Minute)
			case "partial_reset":
				f.sample.Entries[0].Since = f.sample.At
			case "missing":
				f.sample.Entries = nil
			case "explicit_failure":
				f.tracker.Reset()
			}
			r := f.tracker.Observe(f.sample)
			if r.UnknownRegressions != 1 || r.ResolvedRegressions != 0 || r.Regressions[0].DetectedAt != open.Regressions[0].DetectedAt {
				t.Fatal("interruption lost/falsely resolved episode", r)
			}
			if kind == "missing" {
				f.sample.Entries = append([]Counters(nil), fixture().Entries...)
				f.sample = next(f.sample)
				f.tracker.Observe(f.sample)
			}
			if kind == "unavailable" {
				f.sample.Available = true
				f.sample = next(f.sample)
				f.tracker.Observe(f.sample)
			}
			if r = f.observe(10, 1); r.RecoveringRegressions != 1 || r.ResolvedRegressions != 0 {
				t.Fatal("resumed without fresh recovery", r)
			}
			if r = f.observe(10, 1); r.ResolvedRegressions != 1 {
				t.Fatal("did not recover from interruption", r)
			}
		})
	}
}

func TestSQLResetDiscardsUnconfirmedReferenceAndIdleExpiresIt(t *testing.T) {
	f := newRegressionFixture()
	f.warm()
	f.observe(10, 10)
	f.sample = next(f.sample)
	f.sample.Entries[0].Since = f.sample.At
	r := f.tracker.Observe(f.sample)
	if r.PendingRegressions != 0 || r.BaselinedStatements != 0 {
		t.Fatal("partial reset preserved unconfirmed baseline", r)
	}
	f.warm()
	f.tracker.Regressor.MaxIdle = 15 * time.Second
	f.observe(0, 0)
	f.observe(0, 0)
	if r = f.observe(10, 10); r.PendingRegressions != 0 || r.Top[0].Comparison.State != "warming_up" {
		t.Fatal("stale reference was reused", r)
	}
}

func TestSQLAnalysisBeforeTopTruncationAndBoundedOutput(t *testing.T) {
	s := fixture()
	s.Entries = nil
	for n := range 25 {
		s.Entries = append(s.Entries, Counters{Identity: Identity{QueryID: fmt.Sprintf("%02d", n)}, Since: s.ResetAt})
	}
	tracker := &Tracker{Regressor: NewRegressor(3, 2, 3, 5, 5)}
	tracker.Observe(s)
	observe := func(slowAll bool) Report {
		s = next(s)
		for n := range s.Entries {
			calls := int64(1000)
			ms := 1.0
			if n == 24 {
				calls = 5
			}
			if slowAll || (n == 24 && s.Entries[n].Calls >= 15) {
				ms = 10
			}
			s.Entries[n].Calls += calls
			s.Entries[n].TotalExecMS += float64(calls) * ms
		}
		return tracker.Observe(s)
	}
	for range 3 {
		observe(false)
	}
	observe(false)
	r := observe(false)
	if len(r.Top) != TopLimit || r.ActiveRegressions != 1 || r.Regressions[0].QueryID != "24" {
		t.Fatal("SQL outside cost top was not analyzed", r)
	}
	for _, q := range r.Top {
		if q.QueryID == "24" {
			t.Fatal("fixture must remain outside top")
		}
	}
	observe(true)
	r = observe(true)
	if r.ActiveRegressions != 25 || len(r.Regressions) != TopLimit {
		t.Fatal("summary lost episodes after truncation", r)
	}
}

func TestSQLRatiosAndReportsAreIndependent(t *testing.T) {
	f := newRegressionFixture()
	f.warm()
	f.observe(10, 10)
	r := f.observe(10, 10)
	clone := r.Clone()
	*clone.Top[0].Comparison.ExecFactor = 999
	*clone.Regressions[0].Current.Comparison.CallRateFactor = 999
	if *r.Top[0].Comparison.ExecFactor != 10 || *r.Regressions[0].Current.Comparison.CallRateFactor != 1 {
		t.Fatal("reports share comparison pointers")
	}
	*r.Regressions[0].Current.Comparison.ExecFactor = 888
	next := f.observe(0, 0)
	if *next.Regressions[0].Current.Comparison.ExecFactor != 10 {
		t.Fatal("report shares episode state")
	}
	zero := newRegressionFixture()
	for range 3 {
		zero.observe(10, 0)
	}
	z := zero.observe(10, 10)
	if z.Top[0].Comparison.ExecFactor != nil || z.Top[0].Comparison.State != "pending" {
		t.Fatal("zero baseline generated invalid ratio", z)
	}
}
