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

func (s *Store) Update(snapshot collector.Snapshot, incident *detector.Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latest = &snapshot
	s.healthy = true
	if incident != nil {
		s.incidents = append(s.incidents, *incident)
		if len(s.incidents) > 100 {
			s.incidents = s.incidents[1:]
		}
	}
}

func (s *Store) Failed() { s.mu.Lock(); defer s.mu.Unlock(); s.healthy = false }

func (s *Store) View(maxAge time.Duration) View {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := View{Healthy: s.healthy && s.latest != nil && time.Since(s.latest.At) <= maxAge, Incidents: append([]detector.Incident{}, s.incidents...)}
	if s.latest != nil {
		snapshot := *s.latest
		v.Latest = &snapshot
	}
	return v
}
