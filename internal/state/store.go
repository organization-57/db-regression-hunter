package state

import (
	"sync"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

type View struct {
	Latest    *collector.Snapshot `json:"latest"`
	Healthy   bool                `json:"healthy"`
	Incidents []detector.Incident `json:"incidents"`
}

type Store struct {
	mu         sync.RWMutex
	latest     *collector.Snapshot
	healthy    bool
	incidents  []detector.Incident
	sqlHistory []sqlstats.Report
}

func (s *Store) Update(snapshot collector.Snapshot, incident *detector.Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owned := snapshot.Clone()
	s.latest = &owned
	s.healthy = true
	s.sqlHistory = sqlstats.AppendRecent(s.sqlHistory, snapshot.SQL)
	if incident != nil {
		for n := range s.incidents {
			if s.incidents[n].ID == incident.ID {
				s.incidents[n] = incident.Clone()
				return
			}
		}
		s.incidents = append(s.incidents, incident.Clone())
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
	for n := range v.Incidents {
		v.Incidents[n] = v.Incidents[n].Clone()
	}
	if s.latest != nil {
		snapshot := s.latest.Clone()
		v.Latest = &snapshot
	}
	return v
}

type SQLView struct {
	Healthy bool              `json:"healthy"`
	Latest  *sqlstats.Report  `json:"latest"`
	History []sqlstats.Report `json:"history"`
}

func (s *Store) SQLView(maxAge time.Duration) SQLView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := SQLView{History: sqlstats.CloneReports(s.sqlHistory)}
	if s.latest == nil {
		return v
	}
	r := s.latest.SQL.Clone()
	v.Latest = &r
	v.Healthy = s.healthy && time.Since(s.latest.At) <= maxAge && time.Since(r.At) <= maxAge && r.Available && r.Status == "ready"
	return v
}
