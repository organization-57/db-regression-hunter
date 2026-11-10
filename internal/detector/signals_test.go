package detector

import (
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
)

func TestIndependentSignalsAndRecovery(t *testing.T) {
	d := New(Options{BaselineSamples: 3, ConfirmSamples: 2, RecoverySamples: 2, Factor: 3, MaxGap: 3 * time.Second})
	// Detection must not depend on the registration order of the rules.
	d.signals[0], d.signals[3] = d.signals[3], d.signals[0]
	s := collector.Snapshot{At: time.Now(), BlockingGraph: &collector.BlockingGraph{Complete: true}}
	tick := func(age float64, active int, temp, deadlocks int64) []*Incident {
		s.At = s.At.Add(time.Second)
		s.OldestQuerySeconds = age
		s.Active = active
		s.TempBytes += temp
		s.Deadlocks += deadlocks
		return d.Observe(s)
	}
	for range 4 {
		if updates := tick(0, 0, 0, 0); len(updates) != 0 {
			t.Fatal("alert during warmup")
		}
	}
	first := tick(2, 8, 128*1024, 1)
	dead := incidentFor(first, "deadlocks_delta")
	if dead == nil || dead.Finding != FindingDeadlock || !dead.Notify || len(first) != 1 {
		t.Fatal("a single deadlock must open immediately")
	}
	second := tick(3, 8, 128*1024, 1)
	ids := map[string]string{"deadlocks_delta": dead.ID}
	for metric, finding := range map[string]Finding{"oldest_query_seconds": FindingQueryAgeRegression, "active_sessions": FindingActiveSessionsSurge, "temp_bytes_per_second": FindingTempFileGrowth} {
		i := incidentFor(second, metric)
		if i == nil || i.Finding != finding || !i.Notify || i.Status != Open {
			t.Fatalf("missing %s investigation: %+v", metric, i)
		}
		for _, id := range ids {
			if i.ID == id {
				t.Fatal("simultaneous incidents have duplicate IDs")
			}
		}
		ids[metric] = i.ID
	}
	temp := incidentFor(second, "temp_bytes_per_second")
	if temp.Trigger.Observed != 128*1024 || temp.Trigger.Threshold != 64*1024 || temp.Trigger.IntervalSeconds != 1 {
		t.Fatalf("incorrect interval evidence: %+v", temp.Trigger)
	}
	tick(0, 8, 0, 0)
	updates := tick(0, 8, 0, 0)
	for metric, id := range ids {
		i := incidentFor(updates, metric)
		if i == nil || i.ID != id {
			t.Fatal("episode lost or duplicated")
		}
		if metric == "active_sessions" {
			if i.Status != Open || i.Notify {
				t.Fatal("active sessions incorrectly resolved")
			}
			continue
		}
		if i.Status != Resolved || !i.Notify || i.ResolvedAt == nil {
			t.Fatalf("%s did not independently recover", metric)
		}
	}
	tick(0, 0, 0, 0)
	i := incidentFor(tick(0, 0, 0, 0), "active_sessions")
	if i == nil || i.Status != Resolved || i.ID != ids["active_sessions"] {
		t.Fatal("session surge did not recover")
	}
}

func TestCounterBoundariesDoNotInventEvents(t *testing.T) {
	for _, kind := range []string{"stats_reset", "restart", "decrease", "gap", "missing", "clock_reversal"} {
		t.Run(kind, func(t *testing.T) {
			d := New(Options{BaselineSamples: 3, ConfirmSamples: 1, RecoverySamples: 2, Factor: 3, MaxGap: 3 * time.Second})
			s := collector.Snapshot{At: time.Now(), TempBytes: 1000000, Deadlocks: 50}
			for range 4 {
				s.At = s.At.Add(time.Second)
				d.Observe(s)
			}
			s.At = s.At.Add(time.Second)
			s.TempBytes = 2000000
			s.Deadlocks = 60
			switch kind {
			case "stats_reset":
				at := s.At
				s.StatsReset = &at
			case "restart":
				s.PostmasterStart = s.At
			case "decrease":
				s.TempBytes = 0
				s.Deadlocks = 0
			case "gap":
				s.At = s.At.Add(10 * time.Second)
			case "missing":
				d.Missing(s.At)
			case "clock_reversal":
				s.At = s.At.Add(-2 * time.Second)
			}
			if updates := d.Observe(s); len(updates) != 0 {
				t.Fatalf("counter boundary created an event: %+v", updates)
			}
			s.At = s.At.Add(time.Second)
			s.Deadlocks++
			if i := incidentFor(d.Observe(s), "deadlocks_delta"); i == nil || i.Trigger.Observed != 1 {
				t.Fatal("new deadlock after boundary was not detected")
			}
		})
	}
}

func TestSteadyLoadAndTransientSpikes(t *testing.T) {
	d := New(Options{BaselineSamples: 3, ConfirmSamples: 2, RecoverySamples: 2, Factor: 3})
	s := collector.Snapshot{At: time.Now(), Active: 10, OldestQuerySeconds: 2}
	for range 10 {
		s.At = s.At.Add(time.Second)
		s.TempBytes += 128 * 1024
		if len(d.Observe(s)) != 0 {
			t.Fatal("steady high workload was classified as degradation")
		}
	}
	s.At = s.At.Add(time.Second)
	s.Active = 40
	s.TempBytes += 512 * 1024
	if len(d.Observe(s)) != 0 {
		t.Fatal("one spike should not open a sustained anomaly")
	}
	s.At = s.At.Add(time.Second)
	s.Active = 10
	s.TempBytes += 128 * 1024
	if len(d.Observe(s)) != 0 {
		t.Fatal("transient spike did not clear")
	}
}

func TestCounterRecoveryWaitsForFreshIntervalsAfterGap(t *testing.T) {
	d := New(Options{BaselineSamples: 3, ConfirmSamples: 2, RecoverySamples: 2, Factor: 3, MaxGap: 3 * time.Second})
	s := collector.Snapshot{At: time.Now()}
	d.Observe(s)
	s.At = s.At.Add(time.Second)
	s.Deadlocks = 1
	opened := incidentFor(d.Observe(s), "deadlocks_delta")
	s.At = s.At.Add(time.Second)
	d.Observe(s)
	d.Missing(s.At)
	s.At = s.At.Add(time.Second)
	s.Deadlocks = 5
	if i := incidentFor(d.Observe(s), "deadlocks_delta"); i.Status != Open || i.Recovery.NormalSamples != 0 || i.DataGaps != 1 {
		t.Fatal("unobserved interval counted as recovery or a new event")
	}
	s.At = s.At.Add(time.Second)
	d.Observe(s)
	s.At = s.At.Add(time.Second)
	i := incidentFor(d.Observe(s), "deadlocks_delta")
	if i.ID != opened.ID || i.Status != Resolved || i.Recovery.NormalSamples != 2 {
		t.Fatal("counter episode did not recover after fresh zero-delta intervals")
	}
}
