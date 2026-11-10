package detector

import (
	"strings"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
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
	if i == nil || !i.StartedAt.Equal(started) || i.Status != Active || i.Hypothesis != "Блокировки — возможная причина деградации" {
		t.Fatalf("unexpected investigation: %+v", i)
	}
	id := i.ID
	update := observe(5, 2)
	if update == nil || update.ID != id || update.Revision != 2 {
		t.Fatalf("expected same episode update: %+v", update)
	}
	if i.Revision != 1 || len(i.Blocking) != 2 {
		t.Fatal("later observation mutated emitted incident")
	}
	if i = observe(0.2, 0); i.Status != Active || i.RecoverySamples != 1 {
		t.Fatal("one sample must not resolve")
	}
	if i = observe(3, 0); i.Status != Active || i.RecoverySamples != 0 || i.RecoveryStartedAt != nil {
		t.Fatal("relapse must reset recovery")
	}
	observe(0.2, 0)
	i = observe(0.2, 0)
	if i.Status != Resolved || i.ID != id || i.RecoveredAt == nil || i.RecoveryStartedAt == nil || i.RecoverySamples != 2 {
		t.Fatalf("expected confirmed recovery: %+v", i)
	}
	if len(i.Blocking) == 0 {
		t.Fatal("recovery lost original lock evidence")
	}
	if observe(3, 0) != nil {
		t.Fatal("new episode needs confirmation")
	}
	i = observe(4, 0)
	if i == nil || i.ID == id || i.Hypothesis != "Причина пока не установлена: вырос возраст активных запросов" {
		t.Fatalf("expected new episode: %+v", i)
	}
}

func TestBlockingChainCapturedBeforeConfirmation(t *testing.T) {
	d := New(3, 2, 3)
	at := time.Now()
	observe := func(age float64, graph collector.BlockingGraph) *Incident {
		at = at.Add(time.Second)
		return d.Observe(collector.Snapshot{At: at, OldestQuerySeconds: age, LockWaiters: len(graph.Edges), Blocking: graph})
	}
	for range 3 {
		observe(0.2, collector.BlockingGraph{})
	}
	txStart := at.Add(-time.Minute)
	graph := collector.BlockingGraph{
		Sessions: []collector.Session{{PID: 10, State: "active"}, {PID: 20, State: "active"}, {PID: 30, State: "idle in transaction", TransactionStartedAt: &txStart}},
		Edges:    []collector.BlockingEdge{{WaiterPID: 10, BlockerPID: 20}, {WaiterPID: 20, BlockerPID: 30}},
	}
	observe(2, graph)
	// The graph may vanish by the time the age symptom is confirmed.
	graph.Sessions[2].State = "mutated by caller"
	graph.Edges[0].BlockerPID = 99
	i := observe(3, collector.BlockingGraph{})
	if i == nil || len(i.Blocking) != 1 || i.Blocking[0].Graph.Edges[0].BlockerPID != 20 {
		t.Fatalf("onset graph lost: %+v", i)
	}
	evidence := strings.Join(i.Evidence, "\n")
	for _, want := range []string{"PID 10 ждёт PID 20", "PID 20 ждёт PID 30", "idle in transaction"} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("missing %q in %s", want, evidence)
		}
	}
	if i.Hypothesis != "Блокировки — возможная причина деградации" {
		t.Fatal("early lock evidence was ignored")
	}
}

func TestRecoveryRequiresFreshUninterruptedLockFreeSamples(t *testing.T) {
	d := New(3, 2, 3)
	d.MaxSampleGap = 3 * time.Second
	at := time.Now()
	observe := func(age float64, locks int) *Incident {
		at = at.Add(time.Second)
		return d.Observe(collector.Snapshot{At: at, OldestQuerySeconds: age, LockWaiters: locks})
	}
	for range 3 {
		observe(0, 0)
	}
	observe(2, 1)
	opened := observe(3, 1)
	observe(0, 0)
	d.CollectionFailed()
	i := observe(0, 0)
	if i.Status != Active || i.RecoverySamples != 1 || i.CollectionGaps != 1 || i.ID != opened.ID {
		t.Fatalf("outage falsely resolved episode: %+v", i)
	}
	if d.Observe(collector.Snapshot{At: at}) != nil {
		t.Fatal("duplicate snapshot counted")
	}
	if d.Observe(collector.Snapshot{At: at.Add(-time.Second)}) != nil {
		t.Fatal("out-of-order snapshot counted")
	}
	at = at.Add(4 * time.Second)
	i = observe(0, 0)
	if i.Status != Active || i.RecoverySamples != 1 || i.CollectionGaps != 2 {
		t.Fatal("sampling gap did not interrupt recovery")
	}
	i = observe(0, 1)
	if i.Status != Active || i.RecoverySamples != 0 {
		t.Fatal("Lock wait prevents recovery even with low query age")
	}
	observe(0, 0)
	i = observe(0, 0)
	if i.Status != Resolved {
		t.Fatalf("did not recover: %+v", i)
	}
}

func TestBlockingHistoryBoundedAndOnsetPreserved(t *testing.T) {
	d := New(3, 1, 3)
	at := time.Now()
	for range 3 {
		at = at.Add(time.Second)
		d.Observe(collector.Snapshot{At: at})
	}
	var i *Incident
	for n := range 30 {
		at = at.Add(time.Second)
		i = d.Observe(collector.Snapshot{At: at, OldestQuerySeconds: 2, LockWaiters: 1,
			Blocking: collector.BlockingGraph{Edges: []collector.BlockingEdge{{WaiterPID: n + 1, BlockerPID: 100}}}})
	}
	if len(i.Blocking) != maxBlockingObservations || i.BlockingSamplesDropped != 10 {
		t.Fatalf("unbounded history: %+v", i)
	}
	if i.Blocking[0].Graph.Edges[0].WaiterPID != 1 || i.Blocking[len(i.Blocking)-1].Graph.Edges[0].WaiterPID != 30 {
		t.Fatal("lost onset or latest graph")
	}
}

func TestWarmupExcludesKnownLocksAndFailureRestartsConfirmation(t *testing.T) {
	d := New(3, 2, 3)
	at := time.Now()
	observe := func(age float64, locks int) *Incident {
		at = at.Add(time.Second)
		return d.Observe(collector.Snapshot{At: at, OldestQuerySeconds: age, LockWaiters: locks})
	}
	for range 3 {
		observe(100, 1)
	}
	for range 3 {
		if observe(0, 0) != nil {
			t.Fatal("warmup")
		}
	}
	if observe(0.5, 0) != nil {
		t.Fatal("subsecond noise")
	}
	if observe(2, 0) != nil {
		t.Fatal("transient")
	}
	d.CollectionFailed()
	for range 3 {
		if observe(0, 0) != nil {
			t.Fatal("failure should restart warmup")
		}
	}
	if observe(2, 0) != nil {
		t.Fatal("failure should interrupt confirmation")
	}
	if observe(3, 0) == nil {
		t.Fatal("lock-contaminated baseline prevented detection")
	}
}

func TestIncidentPreservesSQLBeforeAndDuringWindows(t *testing.T) {
	d := New(3, 2, 3)
	at := time.Now()
	observe := func(age float64, status string) *Incident {
		at = at.Add(time.Second)
		s := collector.Snapshot{At: at, OldestQuerySeconds: age,
			SQL: sqlstats.Report{At: at, Status: status, Available: status == "ready", Top: []sqlstats.Query{{Identity: sqlstats.Identity{QueryID: "42"}, Calls: 10, MeanExecMS: age}}}}
		i := d.Observe(s)
		s.SQL.Top[0].Calls = 999
		return i
	}
	for range 3 {
		observe(.2, "ready")
	}
	observe(2, "ready")
	opened := observe(3, "ready")
	if opened == nil || len(opened.SQL.Before) != 3 || len(opened.SQL.During) != 2 || opened.SQL.Before[0].Top[0].MeanExecMS != .2 || opened.SQL.During[0].Top[0].MeanExecMS != 2 {
		t.Fatalf("missing SQL windows: %+v", opened)
	}
	if opened.SQL.Before[0].Top[0].Calls != 10 {
		t.Fatal("SQL context shares snapshot data")
	}
	observe(4, "unavailable")
	if len(opened.SQL.During) != 2 {
		t.Fatal("emitted SQL context changed")
	}
	observe(0, "ready")
	resolved := observe(0, "ready")
	if resolved.Status != Resolved || len(resolved.SQL.Before) != 3 || len(resolved.SQL.During) != 5 || resolved.SQL.During[2].Status != "unavailable" {
		t.Fatalf("recovery lost SQL evidence/source gaps: %+v", resolved)
	}
}
