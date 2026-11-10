package state

import (
	"sync"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

func TestIncidentRevisionsAndOwnership(t *testing.T) {
	s := &Store{}
	at := time.Now()
	snapshot := collector.Snapshot{At: at, Blocking: collector.BlockingGraph{
		Edges:    []collector.BlockingEdge{{WaiterPID: 1, BlockerPID: 2}},
		Sessions: []collector.Session{{PID: 2, TransactionStartedAt: &at}},
	}}
	i := detector.Incident{ID: "episode", Status: detector.Active, Revision: 1,
		Evidence: []string{"original"}, Blocking: []detector.BlockingObservation{{Graph: snapshot.Blocking}}}
	s.Update(snapshot, &i)
	snapshot.Blocking.Edges[0].BlockerPID = 999
	i.Evidence[0] = "mutated"
	view := s.View(time.Minute)
	if view.Latest.Blocking.Edges[0].BlockerPID != 2 || view.Incidents[0].Evidence[0] != "original" {
		t.Fatal("store shares caller data")
	}
	*view.Latest.Blocking.Sessions[0].TransactionStartedAt = time.Time{}
	view.Incidents[0].Blocking[0].Graph.Edges[0].BlockerPID = 888
	next := s.View(time.Minute)
	if next.Latest.Blocking.Sessions[0].TransactionStartedAt.IsZero() || next.Incidents[0].Blocking[0].Graph.Edges[0].BlockerPID != 2 {
		t.Fatal("view shares stored data")
	}
	i.Status = detector.Resolved
	i.Revision++
	s.Update(snapshot, &i)
	if v := s.View(time.Minute); len(v.Incidents) != 1 || v.Incidents[0].Status != detector.Resolved {
		t.Fatal("revision appended a duplicate incident")
	}
	// Exercise simultaneous readers while incident revisions are replaced.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			s.View(time.Minute)
		}
	}()
	for range 100 {
		i.Revision++
		s.Update(snapshot, &i)
	}
	wg.Wait()
}

func TestSQLViewAndIncidentContextAreIndependent(t *testing.T) {
	store := &Store{}
	at := time.Now()
	report := sqlstats.Report{At: at, Available: true, Status: "ready", Top: []sqlstats.Query{{Calls: 7}}}
	incident := detector.Incident{ID: "sql", SQL: sqlstats.Context{Before: []sqlstats.Report{report}, During: []sqlstats.Report{report}}}
	store.Update(collector.Snapshot{At: at, SQL: report}, &incident)
	report.Top[0].Calls = -1
	view := store.SQLView(time.Minute)
	if view.Latest.Top[0].Calls != 7 || view.History[0].Top[0].Calls != 7 {
		t.Fatal("store shares SQL caller memory")
	}
	view.Latest.Top[0].Calls = 99
	view.History[0].Top[0].Calls = 99
	all := store.View(time.Minute)
	all.Incidents[0].SQL.Before[0].Top[0].Calls = 99
	if next := store.SQLView(time.Minute); next.Latest.Top[0].Calls != 7 || next.History[0].Top[0].Calls != 7 {
		t.Fatal("SQL view shares stored memory")
	}
	if store.View(time.Minute).Incidents[0].SQL.Before[0].Top[0].Calls != 7 {
		t.Fatal("incident SQL context shares stored memory")
	}
}
