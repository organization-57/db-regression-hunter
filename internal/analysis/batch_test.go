package analysis

import (
	"sort"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/detector"
)

func incident(id, status string, started time.Time) *detector.Incident {
	return &detector.Incident{ID: id, Status: status, StartedAt: started}
}

func ids(batch []detector.Incident) []string {
	var out []string
	for _, i := range batch {
		out = append(out, i.ID)
	}
	sort.Strings(out)
	return out
}

func TestOneDelayedAnalysisForIncidentsOfOneFailure(t *testing.T) {
	t0 := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	b := NewBatcher(25*time.Second, 2*time.Minute)
	if got := b.Observe([]*detector.Incident{incident("age", detector.Open, t0)}, t0, false); got != nil {
		t.Fatal("analysis must wait for related signals")
	}
	b.Observe([]*detector.Incident{incident("sql", detector.Open, t0.Add(10*time.Second)), incident("dead", detector.Resolved, t0.Add(5*time.Second))}, t0.Add(10*time.Second), false)
	if got := b.Observe(nil, t0.Add(25*time.Second), true); got != nil {
		t.Fatal("no new batch while an analysis is running")
	}
	batch := b.Observe(nil, t0.Add(30*time.Second), false)
	if got := ids(batch); len(got) != 3 || got[0] != "age" || got[1] != "dead" || got[2] != "sql" {
		t.Fatalf("one batch with every incident of the failure, including one that already resolved: %v", got)
	}
	if got := b.Observe([]*detector.Incident{incident("age", detector.Open, t0), incident("sql", detector.Recovering, t0)}, t0.Add(40*time.Second), false); got != nil {
		t.Fatal("updates of analysed incidents must not trigger a new analysis")
	}
	b.Observe([]*detector.Incident{incident("sessions", detector.Open, t0.Add(60*time.Second))}, t0.Add(70*time.Second), false)
	if got := b.Observe(nil, t0.Add(100*time.Second), false); got != nil {
		t.Fatal("a new incident waits for the minimum gap")
	}
	if got := ids(b.Observe(nil, t0.Add(150*time.Second), false)); len(got) != 3 {
		t.Fatalf("the next batch adds still open, recent incidents as context: %v", got)
	}
	b.Observe([]*detector.Incident{incident("age", detector.Resolved, t0), incident("sql", detector.Resolved, t0), incident("sessions", detector.Resolved, t0)}, t0.Add(200*time.Second), false)
	if len(b.seen) != 0 || b.Observe(nil, t0.Add(500*time.Second), false) != nil {
		t.Fatalf("resolved and analysed incidents must be forgotten: %+v", b.seen)
	}
}

func TestStuckAndOldIncidentsStayOutOfNewBatches(t *testing.T) {
	t0 := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	b := NewBatcher(25*time.Second, 2*time.Minute)
	gone := incident("gone-sql", detector.Open, t0)
	gone.SQLRegression = &detector.SQLRegression{Status: "unknown"}
	if b.Observe([]*detector.Incident{gone}, t0, false); b.Observe(nil, t0.Add(time.Minute), false) != nil {
		t.Fatal("an unknown SQL episode alone must not trigger an analysis")
	}
	old := incident("old", detector.Open, t0)
	b.Observe([]*detector.Incident{old}, t0, false)
	if got := ids(b.Observe(nil, t0.Add(30*time.Second), false)); len(got) != 1 || got[0] != "old" {
		t.Fatalf("first batch %v", got)
	}
	later := t0.Add(30 * time.Minute)
	b.Observe([]*detector.Incident{gone, old, incident("new", detector.Open, later)}, later, false)
	if got := ids(b.Observe(nil, later.Add(30*time.Second), false)); len(got) != 1 || got[0] != "new" {
		t.Fatalf("stuck and long-analysed incidents must not drag the window back: %v", got)
	}
}

func TestResultsReplaceByIDAndPreferTheModelAnswer(t *testing.T) {
	var s Results
	s.Put(Result{ID: "1", IncidentIDs: []string{"a", "b"}, Status: Pending})
	s.Put(Result{ID: "1", IncidentIDs: []string{"a", "b"}, Status: Done})
	s.Put(Result{ID: "2", IncidentIDs: []string{"a", "c"}, Status: Fallback})
	s.Put(Result{ID: "3", IncidentIDs: []string{"c", "d"}, Status: Pending})
	if r, ok := s.ForIncident("a"); !ok || r.ID != "1" || len(s.All()) != 3 {
		t.Fatalf("a later fallback must not hide an earlier model answer: %+v %v", r, ok)
	}
	if r, _ := s.ForIncident("c"); r.ID != "2" {
		t.Fatalf("a finished fallback beats a newer pending analysis: %+v", r)
	}
	if r, _ := s.ForIncident("d"); r.Status != Pending {
		t.Fatalf("a running analysis is shown as pending: %+v", r)
	}
	if _, ok := s.ForIncident("z"); ok {
		t.Fatal("unknown incident")
	}
	for n := 0; n < 60; n++ {
		s.Put(Result{ID: string(rune('A' + n))})
	}
	if len(s.All()) != keptResults {
		t.Fatalf("kept %d", len(s.All()))
	}
}
