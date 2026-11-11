package detector

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

type sqlFixture struct {
	d         *Detector
	tracker   *sqlstats.Tracker
	raw       sqlstats.Snapshot
	deadlocks int64
}

func newSQLFixture(count int) *sqlFixture {
	at := time.Now().UTC()
	regressor := sqlstats.NewRegressor(3, 2, 3, 5, 5)
	regressor.RecoveryIntervals = 3
	f := &sqlFixture{d: New(Options{BaselineSamples: 3, ConfirmSamples: 2, RecoverySamples: 3, Factor: 3, MaxGap: 5 * time.Second}), tracker: &sqlstats.Tracker{Regressor: regressor, MaxSampleGap: 5 * time.Second}, raw: sqlstats.Snapshot{Available: true, At: at, ServerStartedAt: at.Add(-time.Hour), ResetAt: at.Add(-time.Minute)}}
	for n := range count {
		f.raw.Entries = append(f.raw.Entries, sqlstats.Counters{Identity: sqlstats.Identity{DatabaseID: 1, UserID: 2, QueryID: fmt.Sprint(n), TopLevel: true}, Since: at.Add(-time.Minute)})
	}
	f.tick(0, 0)
	for range 3 {
		f.tick(5, 1)
	}
	return f
}

func (f *sqlFixture) tick(calls int64, means ...float64) ([]*Incident, sqlstats.Report) {
	f.raw.At = f.raw.At.Add(time.Second)
	for n := range f.raw.Entries {
		mean := means[min(n, len(means)-1)]
		f.raw.Entries[n].Calls += calls
		f.raw.Entries[n].TotalExecMS += float64(calls) * mean
	}
	report := f.tracker.Observe(f.raw)
	snapshot := collector.Snapshot{At: f.raw.At, OldestQuerySeconds: .2, Deadlocks: f.deadlocks, SQL: report, BlockingGraph: &collector.BlockingGraph{Complete: true}}
	return f.d.Observe(snapshot), report
}

func sqlIncident(updates []*Incident, id string) *Incident {
	for _, i := range updates {
		if i.SQLRegression != nil && i.SQLRegression.QueryID == id {
			return i
		}
	}
	return nil
}

func TestSQLIncidentUsesNewModelAndSeparateRecoverySetting(t *testing.T) {
	f := newSQLFixture(1)
	if updates, _ := f.tick(5, 10); sqlIncident(updates, "0") != nil {
		t.Fatal("transient SQL spike alerted")
	}
	updates, _ := f.tick(5, 10)
	opened := sqlIncident(updates, "0")
	if opened == nil || opened.Status != Open || !opened.Notify || !opened.HasFinding(FindingSQLExecutionRegression) || opened.Trigger.Metric != "sql_mean_exec_ms" || opened.Trigger.Baseline != 1 || opened.Trigger.Threshold != 6 || opened.Recovery.RequiredSamples != 3 {
		t.Fatalf("bad SQL opening: %+v", opened)
	}

	collections := 0
	f.d.EnrichQueries(updates, func(targets []collector.QueryTarget) collector.QueryBatch {
		collections++
		if len(targets) != 1 || targets[0].Statement == nil || targets[0].Statement.QueryID != "0" {
			t.Fatal("wrong query selected")
		}
		return collector.QueryBatch{Details: []json.RawMessage{json.RawMessage(`{"sql":"select 1"}`)}}
	})
	opened.Queries[0].Details[8] = 'X'
	first := CloneIncident(*opened)
	updates, _ = f.tick(5, 1)
	f.d.EnrichQueries(updates, func([]collector.QueryTarget) collector.QueryBatch { collections++; return collector.QueryBatch{} })
	if i := sqlIncident(updates, "0"); collections != 1 || string(i.Queries[0].Details) != `{"sql":"select 1"}` {
		t.Fatal("details were recollected or shared with caller")
	}
	if i := sqlIncident(updates, "0"); i.Status != Recovering || i.Notify || i.Recovery.NormalSamples != 1 {
		t.Fatal("first recovery", i)
	}
	updates, _ = f.tick(5, 1)
	if i := sqlIncident(updates, "0"); i.Status != Recovering || i.Recovery.NormalSamples != 2 {
		t.Fatal("recovery used confirm count instead of RECOVERY_SAMPLES", i)
	}
	updates, _ = f.tick(5, 1)
	closed := sqlIncident(updates, "0")
	if closed.Status != Resolved || !closed.Notify || closed.ID != opened.ID || closed.ResolvedAt == nil {
		t.Fatal("recovery failed", closed)
	}
	if first.SQLRegression.Status != "active" || first.Trigger.Baseline != 1 {
		t.Fatal("later updates changed initial evidence")
	}
}

func TestSQLUnknownAndCollectionFailureKeepSameEpisode(t *testing.T) {
	f := newSQLFixture(1)
	f.tick(5, 10)
	updates, _ := f.tick(5, 10)
	opened := sqlIncident(updates, "0")
	updates, _ = f.tick(0, 0)
	if i := sqlIncident(updates, "0"); i.ID != opened.ID || i.Status != Open || i.SQLRegression.Status != "unknown" || i.Recovery.NormalSamples != 0 || i.DataGaps != 1 {
		t.Fatal("idle falsely resolved", i)
	}
	f.tracker.Reset()
	missing := f.d.Missing(f.raw.At)
	if i := sqlIncident(missing, "0"); i.Status != Open || i.Notify || i.DataGaps != 2 {
		t.Fatal("missing update lost episode", i)
	}
	updates, _ = f.tick(5, 1)
	if i := sqlIncident(updates, "0"); i.ID != opened.ID || i.SQLRegression.Status != "unknown" || i.Recovery.NormalSamples != 0 {
		t.Fatal("warmup counted toward recovery", i)
	}
	for n := range 3 {
		updates, _ = f.tick(5, 1)
		i := sqlIncident(updates, "0")
		if i.ID != opened.ID || i.Recovery.NormalSamples != n+1 {
			t.Fatal("recovery did not restart", i)
		}
	}
	if sqlIncident(updates, "0").Status != Resolved {
		t.Fatal("SQL remained open")
	}
}

func TestSQLParallelEpisodesAndExistingDeadlockSignalStayIndependent(t *testing.T) {
	f := newSQLFixture(2)
	f.deadlocks++
	f.tick(5, 10, 10)
	f.deadlocks++
	updates, _ := f.tick(5, 10, 10)
	a, b := sqlIncident(updates, "0"), sqlIncident(updates, "1")
	dead := incidentFor(updates, "deadlocks_delta")
	if a == nil || b == nil || a.ID == b.ID || dead == nil || !dead.HasFinding(FindingDeadlock) {
		t.Fatal("SQL damaged parallel signals", updates)
	}
	for range 3 {
		updates, _ = f.tick(5, 1, 10)
	}
	if i := sqlIncident(updates, "0"); i.Status != Resolved || i.ID != a.ID {
		t.Fatal("first SQL did not independently recover", i)
	}
	if i := sqlIncident(updates, "1"); i.Status != Open || i.ID != b.ID {
		t.Fatal("resolving one SQL closed another", i)
	}
	if i := incidentFor(updates, "deadlocks_delta"); i == nil || i.Status != Resolved {
		t.Fatal("deadlock recovery was tied to SQL", i)
	}
}

func TestAllSQLIncidentsAreDelivered(t *testing.T) {
	f := newSQLFixture(25)
	f.tick(5, 10)
	updates, report := f.tick(5, 10)
	if len(report.Queries) != 25 || len(report.Episodes) != 25 || report.ActiveRegressions != 25 || len(updates) != 25 {
		t.Fatal("lost SQL incidents", len(updates), report.ActiveRegressions)
	}
	ids := map[string]bool{}
	for _, i := range updates {
		if !i.HasFinding(FindingSQLExecutionRegression) || !i.Notify || ids[i.ID] {
			t.Fatal("duplicate/invalid SQL incident", i)
		}
		ids[i.ID] = true
	}
}
