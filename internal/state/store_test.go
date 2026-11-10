package state

import (
	"fmt"
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
	for n := range 101 {
		s.Update(collector.Snapshot{At: time.Now()}, &detector.Incident{ID: fmt.Sprint(n), Hypothesis: fmt.Sprint("hypothesis ", n), Evidence: []string{"evidence"}, NextSteps: []string{"next step"}})
	}
	s.Failed()
	for _, id := range []string{"1", "50", "100"} {
		i, ok := s.IncidentByID(id)
		if !ok || i.ID != id || i.Hypothesis != "hypothesis "+id {
			t.Fatal("incorrect incident", i, ok)
		}
		i.Evidence[0], i.NextSteps[0] = "changed", "changed"
		again, _ := s.IncidentByID(id)
		if again.Evidence[0] != "evidence" || again.NextSteps[0] != "next step" {
			t.Fatal("lookup exposes mutable store data")
		}
	}
	for _, id := range []string{"0", "missing", ""} {
		if _, ok := s.IncidentByID(id); ok {
			t.Fatal("found missing or evicted incident", id)
		}
	}
}
