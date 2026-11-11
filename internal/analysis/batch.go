package analysis

import (
	"sync"
	"time"

	"github.com/makeev/db-regression-hunter/internal/detector"
)

const contextAge = 10 * time.Minute

type Batcher struct {
	delay, minGap time.Duration
	seen          map[string]detector.Incident
	done          map[string]bool
	due, last     time.Time
}

func NewBatcher(delay, minGap time.Duration) *Batcher {
	return &Batcher{delay: delay, minGap: minGap, seen: map[string]detector.Incident{}, done: map[string]bool{}}
}

func stuck(i detector.Incident) bool {
	return i.SQLRegression != nil && i.SQLRegression.Status == "unknown"
}

func (b *Batcher) Observe(updates []*detector.Incident, now time.Time, busy bool) []detector.Incident {
	for _, u := range updates {
		if u != nil {
			b.seen[u.ID] = detector.CloneIncident(*u)
		}
	}
	pending := false
	for id, i := range b.seen {
		if !b.done[id] && !stuck(i) {
			pending = true
		}
	}
	if !pending {
		b.due = time.Time{}
		b.prune()
		return nil
	}
	if b.due.IsZero() {
		b.due = now.Add(b.delay)
		if !b.last.IsZero() && b.due.Before(b.last.Add(b.minGap)) {
			b.due = b.last.Add(b.minGap)
		}
	}
	if busy || now.Before(b.due) {
		return nil
	}
	var batch []detector.Incident
	for id, i := range b.seen {
		fresh := !b.done[id]
		if stuck(i) || (!fresh && (i.Status == detector.Resolved || now.Sub(i.StartedAt) > contextAge)) {
			continue
		}
		batch = append(batch, i)
		b.done[id] = true
	}
	b.due, b.last = time.Time{}, now
	b.prune()
	return batch
}

func (b *Batcher) prune() {
	for id, i := range b.seen {
		if i.Status == detector.Resolved && b.done[id] {
			delete(b.seen, id)
			delete(b.done, id)
		}
	}
}

type Results struct {
	mu    sync.Mutex
	items []Result
}

const keptResults = 50

func (s *Results) Put(r Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for n := range s.items {
		if s.items[n].ID == r.ID {
			s.items[n] = r
			return
		}
	}
	s.items = append(s.items, r)
	if len(s.items) > keptResults {
		s.items = append([]Result{}, s.items[len(s.items)-keptResults:]...)
	}
}

func (s *Results) All() []Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Result{}, s.items...)
}

var preference = map[string]int{Done: 3, Fallback: 2, Pending: 1}

func (s *Results) ForIncident(id string) (Result, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	best := -1
	for n := len(s.items) - 1; n >= 0; n-- {
		if contains(s.items[n].IncidentIDs, id) && (best < 0 || preference[s.items[n].Status] > preference[s.items[best].Status]) {
			best = n
		}
	}
	if best < 0 {
		return Result{}, false
	}
	return s.items[best], true
}
