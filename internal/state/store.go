package state

import (
	"sync"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/detector"
)

type View struct {
	Latest    *collector.Snapshot `json:"latest"`
	Healthy   bool                `json:"healthy"`
	Incidents []detector.Incident `json:"incidents"`
}

type Store struct {
	mu        sync.RWMutex
	latest    *collector.Snapshot
	healthy   bool
	incidents []detector.Incident
}

func (s *Store) Update(snapshot collector.Snapshot, incidents ...*detector.Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	latest := collector.CloneSnapshot(snapshot)
	s.latest = &latest
	s.healthy = true
	for _, incident := range incidents {
		s.upsert(incident)
	}
}

func (s *Store) Failed(incidents ...*detector.Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = false
	for _, incident := range incidents {
		s.upsert(incident)
	}
}

func (s *Store) upsert(update *detector.Incident) {
	if update == nil {
		return
	}
	i := detector.CloneIncident(*update)
	for n := range s.incidents {
		if s.incidents[n].ID == i.ID {
			s.incidents[n] = i
			return
		}
	}
	s.incidents = append(s.incidents, i)
	if len(s.incidents) > 100 {
		for n, old := range s.incidents {
			if old.Status == detector.Resolved {
				copy(s.incidents[n:], s.incidents[n+1:])
				s.incidents[len(s.incidents)-1] = detector.Incident{}
				s.incidents = s.incidents[:len(s.incidents)-1]
				break
			}
		}
	}
}

// IncidentByID searches retained incidents independently of collection health.
func (s *Store) IncidentByID(id string) (detector.Incident, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, incident := range s.incidents {
		if incident.ID == id {
			return detector.CloneIncident(incident), true
		}
	}
	return detector.Incident{}, false
}

func (s *Store) View(maxAge time.Duration, details bool) View {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := View{Healthy: s.healthy && s.latest != nil && time.Since(s.latest.At) <= maxAge, Incidents: []detector.Incident{}}
	for _, i := range s.incidents {
		if details {
			v.Incidents = append(v.Incidents, detector.CloneIncident(i))
		} else {
			v.Incidents = append(v.Incidents, detector.Incident{Status: i.Status})
		}
	}
	if s.latest != nil {
		snapshot := *s.latest
		snapshot.BlockingGraph = nil
		if details {
			snapshot = collector.CloneSnapshot(*s.latest)
		}
		v.Latest = &snapshot
	}
	return v
}
