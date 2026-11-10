package detector

import (
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
)

func graph(at time.Time) *collector.BlockingGraph {
	backend := at.Add(-time.Hour)
	return &collector.BlockingGraph{At: at, Complete: true, Nodes: []collector.Session{
		{PID: 11, BackendStart: &backend, TargetDatabase: true, State: "active", BlockedBy: []int{22}},
		{PID: 22, BackendStart: &backend, TargetDatabase: true, State: "active", BlockedBy: []int{33}},
		{PID: 33, BackendStart: &backend, TargetDatabase: true, State: "idle in transaction", TransactionAgeSeconds: 42, Application: "checkout"},
	}}
}

func TestBlockerChainRecoveryRelapseAndGaps(t *testing.T) {
	d := New(Options{BaselineSamples: 3, ConfirmSamples: 2, RecoverySamples: 3, Factor: 3, MaxGap: 5 * time.Second})
	at := time.Now().UTC()
	observe := func(age float64, locks int, g *collector.BlockingGraph) *Incident {
		at = at.Add(time.Second)
		if g != nil {
			g.At = at
		}
		return observeQuery(d, collector.Snapshot{At: at, OldestQuerySeconds: age, LockWaiters: locks, BlockingGraph: g})
	}
	normal := func() *Incident { return observe(0, 0, &collector.BlockingGraph{Complete: true}) }
	for range 3 {
		normal()
	}
	observe(2, 2, graph(at))
	i := observe(3, 2, graph(at))
	if i == nil || !i.Notify || len(i.Blockers) != 1 || i.Blockers[0].PID != 33 || len(i.Blockers[0].Chains[0]) != 3 {
		t.Fatalf("missing actual root/chain: %+v", i)
	}
	id := i.ID
	i.Blockers[0].PID = 999 // Returned evidence must not mutate detector state.
	if got := normal(); got.Status != Recovering || got.Recovery.NormalSamples != 1 || got.Notify {
		t.Fatalf("premature recovery: %+v", got)
	}
	if got := observe(3, 1, graph(at)); got.Status != Open || got.ID != id || got.Notify {
		t.Fatalf("relapse created duplicate incident: %+v", got)
	}
	normal()
	d.Missing(at.Add(time.Second))
	if got := normal(); got.Recovery.NormalSamples != 1 || got.DataGaps != 1 {
		t.Fatalf("gap did not reset confirmation: %+v", got)
	}
	if got := observe(0, 0, &collector.BlockingGraph{Complete: false}); got.Status != Open || got.Recovery.NormalSamples != 0 {
		t.Fatal("incomplete graph counted as recovery")
	}
	normal()
	normal()
	resolved := normal()
	if resolved.Status != Resolved || !resolved.Notify || resolved.ID != id || resolved.ResolvedAt == nil || resolved.Blockers[0].PID != 33 {
		t.Fatalf("invalid resolved report: %+v", resolved)
	}
	if normal() != nil {
		t.Fatal("resolved episode should not emit more updates")
	}
}

func TestUnknownPreparedAndCyclicBlockersNotInvented(t *testing.T) {
	for _, kind := range []string{"missing", "prepared", "cycle"} {
		t.Run(kind, func(t *testing.T) {
			g := graph(time.Now())
			switch kind {
			case "missing":
				g.Nodes = g.Nodes[:2]
			case "prepared":
				g.Nodes[1].BlockedBy = []int{0}
			case "cycle":
				g.Nodes[2].BlockedBy = []int{11}
			}
			if roots := findBlockers(g); len(roots) != 0 {
				t.Fatalf("invented root: %+v", roots)
			}
		})
	}
}

func TestBlockerReferencesFollowEvidenceGraph(t *testing.T) {
	d := New(Options{BaselineSamples: 3, ConfirmSamples: 1, RecoverySamples: 1, Factor: 3})
	at := time.Now()
	for range 3 {
		at = at.Add(time.Second)
		observeQuery(d, collector.Snapshot{At: at})
	}
	i := observeQuery(d, collector.Snapshot{At: at.Add(time.Second), OldestQuerySeconds: 3, LockWaiters: 2, BlockingGraph: graph(at)})
	if i.Blockers[0].PID != 33 {
		t.Fatal("initial root missing")
	}
	g := graph(at.Add(2 * time.Second))
	g.Nodes[2].PID = 44
	g.Nodes[1].BlockedBy = []int{44}
	i = observeQuery(d, collector.Snapshot{At: g.At, OldestQuerySeconds: 4, LockWaiters: 2, BlockingGraph: g})
	if len(i.Blockers) != 1 || i.Blockers[0].PID != 44 || i.Blockers[0].Chains[0][2] != 44 || i.BlockingGraph.Nodes[2].PID != 44 {
		t.Fatal("blocker references and evidence graph must be replaced together")
	}
	i = observeQuery(d, collector.Snapshot{At: g.At.Add(time.Second), BlockingGraph: &collector.BlockingGraph{Complete: true}})
	if i.Status != Resolved || i.Blockers[0].PID != 44 || i.BlockingGraph.Nodes[2].PID != 44 {
		t.Fatal("resolution lost the observed graph")
	}
}

func TestLongSamplingGapDoesNotConfirmRecovery(t *testing.T) {
	d := New(Options{BaselineSamples: 3, ConfirmSamples: 1, RecoverySamples: 2, Factor: 3, MaxGap: 3 * time.Second})
	at := time.Now()
	s := collector.Snapshot{At: at, BlockingGraph: &collector.BlockingGraph{Complete: true}}
	for range 3 {
		s.At = s.At.Add(time.Second)
		observeQuery(d, s)
	}
	s.At = s.At.Add(time.Second)
	s.OldestQuerySeconds = 3
	observeQuery(d, s)
	s.OldestQuerySeconds = 0
	s.At = s.At.Add(time.Second)
	observeQuery(d, s)
	s.At = s.At.Add(10 * time.Second)
	i := observeQuery(d, s)
	if i.Status != Recovering || i.Recovery.NormalSamples != 1 || i.DataGaps != 1 {
		t.Fatalf("sampling gap incorrectly confirmed recovery: %+v", i)
	}
}
