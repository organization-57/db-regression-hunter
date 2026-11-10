package state

import (
	"strconv"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/detector"
)

func TestIncidentByID(t *testing.T) {
	s := &Store{}
	if _, ok := s.IncidentByID("missing"); ok {
		t.Fatal("empty store returned an incident")
	}
	at := time.Now().UTC()
	for n := range 101 {
		status := detector.Resolved
		if n == 100 {
			status = detector.Open
		}
		s.Update(collector.Snapshot{At: at}, &detector.Incident{
			ID: strconv.Itoa(n), Status: status, Finding: detector.FindingLockContention,
			BlockingGraph: &collector.BlockingGraph{Nodes: []collector.Session{{PID: 33}}},
			Blockers:      []detector.Blocker{{PID: 33, Chains: [][]int{{11, 33}}}},
		})
	}
	s.Failed(nil)
	for _, id := range []string{"1", "50", "100"} {
		i, ok := s.IncidentByID(id)
		if !ok || i.ID != id || i.Finding != "lock_contention" {
			t.Fatal("incorrect incident", i, ok)
		}
		i.BlockingGraph.Nodes[0].PID = 999
		i.Blockers[0].Chains[0][0] = 999
		again, _ := s.IncidentByID(id)
		if again.BlockingGraph.Nodes[0].PID != 33 || again.Blockers[0].Chains[0][0] != 11 {
			t.Fatal("lookup exposes mutable store data")
		}
	}
	for _, id := range []string{"0", "missing", ""} {
		if _, ok := s.IncidentByID(id); ok {
			t.Fatal("found missing or evicted incident", id)
		}
	}
	update, _ := s.IncidentByID("100")
	update.Status = detector.Resolved
	s.Update(collector.Snapshot{At: at}, &update)
	resolved, _ := s.IncidentByID("100")
	if resolved.Status != detector.Resolved || len(s.View(time.Minute, true).Incidents) != 100 {
		t.Fatal("lookup must return updated incident without duplication")
	}
}

func TestIncidentUpdatesAndCopies(t *testing.T) {
	s := &Store{}
	at := time.Now().UTC()
	graph := &collector.BlockingGraph{At: at, Complete: true, Nodes: []collector.Session{{PID: 33}}}
	i := &detector.Incident{ID: "episode", Status: detector.Open, BlockingGraph: graph, Blockers: []detector.Blocker{{PID: 33, Chains: [][]int{{11, 33}}}}}
	s.Update(collector.Snapshot{At: at, BlockingGraph: graph}, i)
	i.Status = detector.Resolved
	s.Update(collector.Snapshot{At: at}, i)
	v := s.View(time.Minute, true)
	if len(v.Incidents) != 1 || v.Incidents[0].Status != detector.Resolved {
		t.Fatal("incident duplicated or not updated")
	}
	v.Incidents[0].BlockingGraph.Nodes[0].PID = 999
	v.Incidents[0].Blockers[0].Chains[0][0] = 999
	copy := s.View(time.Minute, true).Incidents[0]
	if copy.BlockingGraph.Nodes[0].PID != 33 || copy.Blockers[0].Chains[0][0] != 11 {
		t.Fatal("API result aliases retained evidence")
	}
	for n := 0; n < 101; n++ {
		s.Update(collector.Snapshot{At: at}, &detector.Incident{ID: strconv.Itoa(n), Status: detector.Resolved})
	}
	if len(s.incidents) != 100 || s.incidents[0].ID != "1" {
		t.Fatal("incident retention is not bounded")
	}
}

func TestMetricsViewOmitsReportAndGraphCopies(t *testing.T) {
	s := &Store{}
	s.Update(collector.Snapshot{At: time.Now(), BlockingGraph: &collector.BlockingGraph{Complete: true}}, &detector.Incident{ID: "episode", Status: detector.Open})
	metrics := s.View(time.Minute, false)
	if !metrics.Healthy || metrics.Latest.BlockingGraph != nil || metrics.Incidents[0].ID != "" || metrics.Incidents[0].Status != detector.Open {
		t.Fatal("metrics view should retain only scalar metrics and incident statuses")
	}
	if s.View(time.Minute, true).Incidents[0].ID != "episode" {
		t.Fatal("metrics read mutated the report")
	}
}

func TestParallelEpisodesAreUpdatedAndRetained(t *testing.T) {
	s := &Store{}
	snapshot := collector.Snapshot{At: time.Now()}
	a, b := &detector.Incident{ID: "a", Status: detector.Open}, &detector.Incident{ID: "b", Status: detector.Open}
	s.Update(snapshot, a, b)
	a.Status = detector.Resolved
	s.Update(snapshot, a)
	if len(s.incidents) != 2 || s.incidents[0].Status != detector.Resolved || s.incidents[1].Status != detector.Open {
		t.Fatal("updating one metric duplicated or closed another episode")
	}
	for n := 0; n < 105; n++ {
		s.Update(snapshot, &detector.Incident{ID: strconv.Itoa(n), Status: detector.Resolved})
	}
	if len(s.incidents) != 100 || s.incidents[0].ID != "b" {
		t.Fatal("retention evicted an open episode")
	}
}
