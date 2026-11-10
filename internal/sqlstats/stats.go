// Package sqlstats derives interval metrics from pg_stat_statements counters.
// It does not collect SQL texts or infer regressions from cumulative averages.
package sqlstats

import (
	"math"
	"sort"
	"time"
)

const TopLimit = 20

// QueryID is a decimal string so JSON clients cannot lose bigint precision.
// All four fields belong to the PostgreSQL statistics entry identity.
type Identity struct {
	DatabaseID uint32 `json:"database_id"`
	UserID     uint32 `json:"user_id"`
	QueryID    string `json:"query_id"`
	TopLevel   bool   `json:"top_level"`
}

type Counters struct {
	Identity
	Since                                                time.Time
	Calls                                                int64
	TotalExecMS                                          float64
	SharedReads, SharedHits, TempReads, TempWrites, Rows int64
}

// Snapshot is an internal, complete sample for one database, excluding the
// monitoring role. Unavailable/partial samples must never be used as zeroes.
type Snapshot struct {
	At                       time.Time
	Available                bool
	Reason                   string
	ServerStartedAt, ResetAt time.Time
	Deallocations            int64
	Entries                  []Counters
}

type Query struct {
	Identity
	Calls              int64   `json:"calls"`
	TotalExecMS        float64 `json:"total_exec_ms"`
	CallsPerSecond     float64 `json:"calls_per_second"`
	MeanExecMS         float64 `json:"mean_exec_ms"`
	SharedReadsPerCall float64 `json:"shared_reads_per_call"`
	SharedHitsPerCall  float64 `json:"shared_hits_per_call"`
	TempReadsPerCall   float64 `json:"temp_reads_per_call"`
	TempWritesPerCall  float64 `json:"temp_writes_per_call"`
	RowsPerCall        float64 `json:"rows_per_call"`
}

type Report struct {
	Available          bool      `json:"available"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason,omitempty"`
	From               time.Time `json:"from"`
	At                 time.Time `json:"at"`
	IntervalSeconds    float64   `json:"interval_seconds"`
	ObservedStatements int       `json:"observed_statements"`
	NewStatements      int       `json:"new_statements"`
	ResetStatements    int       `json:"reset_statements"`
	MissingStatements  int       `json:"missing_statements"`
	ActiveStatements   int       `json:"active_statements"`
	Top                []Query   `json:"top"`
}

func (r Report) Clone() Report {
	r.Top = append([]Query(nil), r.Top...)
	return r
}

// Tracker is owned by the collection loop. Only adjacent complete snapshots
// from the same statistics generation can produce a valid interval.
type Tracker struct {
	MaxSampleGap time.Duration
	previous     *Snapshot
	entries      map[Identity]Counters
}

func (t *Tracker) Reset() { t.previous = nil; t.entries = nil }

func (t *Tracker) seed(s Snapshot) {
	t.entries = make(map[Identity]Counters, len(s.Entries))
	for _, entry := range s.Entries {
		t.entries[entry.Identity] = entry
	}
	s.Entries = nil
	t.previous = &s
}

func (t *Tracker) Observe(s Snapshot) Report {
	r := Report{At: s.At, Available: s.Available, ObservedStatements: len(s.Entries), Top: []Query{}}
	if !s.Available || s.At.IsZero() {
		r.Available = false
		r.Status = "unavailable"
		r.Reason = s.Reason
		if r.Reason == "" {
			r.Reason = "invalid_sample"
		}
		t.Reset()
		return r
	}
	if t.previous == nil {
		t.seed(s)
		r.Status = "warming_up"
		return r
	}
	previous := t.previous
	if !s.At.After(previous.At) {
		r.Status = "stale"
		r.Reason = "non_monotonic_timestamp"
		return r // Do not replace the last usable sample with an old one.
	}
	duration := s.At.Sub(previous.At)
	if !s.ServerStartedAt.Equal(previous.ServerStartedAt) || !s.ResetAt.Equal(previous.ResetAt) || s.Deallocations != previous.Deallocations {
		t.seed(s)
		r.Status = "reset"
		r.Reason = "statistics_generation_changed"
		return r
	}
	if t.MaxSampleGap > 0 && duration > t.MaxSampleGap {
		t.seed(s)
		r.Status = "gap"
		r.Reason = "sampling_gap"
		return r
	}
	r.Status = "ready"
	r.From = previous.At
	r.IntervalSeconds = duration.Seconds()
	seen := make(map[Identity]bool, len(s.Entries))
	for _, current := range s.Entries {
		seen[current.Identity] = true
		old, exists := t.entries[current.Identity]
		if !exists {
			r.NewStatements++
			continue
		}
		if !current.Since.Equal(old.Since) || !validDelta(old, current) {
			r.ResetStatements++
			continue
		}
		calls := current.Calls - old.Calls
		if calls == 0 {
			continue
		}
		n := float64(calls)
		elapsed := current.TotalExecMS - old.TotalExecMS
		r.Top = append(r.Top, Query{
			Identity: current.Identity, Calls: calls, TotalExecMS: elapsed,
			CallsPerSecond: n / r.IntervalSeconds, MeanExecMS: elapsed / n,
			SharedReadsPerCall: float64(current.SharedReads-old.SharedReads) / n,
			SharedHitsPerCall:  float64(current.SharedHits-old.SharedHits) / n,
			TempReadsPerCall:   float64(current.TempReads-old.TempReads) / n,
			TempWritesPerCall:  float64(current.TempWrites-old.TempWrites) / n,
			RowsPerCall:        float64(current.Rows-old.Rows) / n,
		})
	}
	for id := range t.entries {
		if !seen[id] {
			r.MissingStatements++
		}
	}
	sort.Slice(r.Top, func(i, j int) bool {
		a, b := r.Top[i], r.Top[j]
		if a.TotalExecMS != b.TotalExecMS {
			return a.TotalExecMS > b.TotalExecMS
		}
		if a.DatabaseID != b.DatabaseID {
			return a.DatabaseID < b.DatabaseID
		}
		if a.UserID != b.UserID {
			return a.UserID < b.UserID
		}
		if a.QueryID != b.QueryID {
			return a.QueryID < b.QueryID
		}
		return a.TopLevel && !b.TopLevel
	})
	r.ActiveStatements = len(r.Top)
	if len(r.Top) > TopLimit {
		r.Top = r.Top[:TopLimit]
	}
	t.seed(s)
	return r
}

func validDelta(a, b Counters) bool {
	if b.Since.IsZero() || a.Calls < 0 || b.Calls < a.Calls || a.TotalExecMS < 0 || b.TotalExecMS < a.TotalExecMS || math.IsNaN(a.TotalExecMS) || math.IsNaN(b.TotalExecMS) || math.IsInf(a.TotalExecMS, 0) || math.IsInf(b.TotalExecMS, 0) {
		return false
	}
	for _, pair := range [][2]int64{{a.SharedReads, b.SharedReads}, {a.SharedHits, b.SharedHits}, {a.TempReads, b.TempReads}, {a.TempWrites, b.TempWrites}, {a.Rows, b.Rows}} {
		if pair[0] < 0 || pair[1] < pair[0] {
			return false
		}
	}
	return true
}

const HistoryLimit = 20

// Context preserves a bounded before/during window for an incident. Rankings
// are evidence about interval cost, not proof that a SQL statement regressed.
type Context struct {
	Before  []Report `json:"before"`
	During  []Report `json:"during"`
	Dropped int      `json:"dropped"`
}

func CloneReports(reports []Report) []Report {
	result := make([]Report, len(reports))
	for n := range reports {
		result[n] = reports[n].Clone()
	}
	return result
}

func (c Context) Clone() Context {
	c.Before = CloneReports(c.Before)
	c.During = CloneReports(c.During)
	return c
}

func (c *Context) Observe(r Report) {
	if r.Status == "" {
		return
	}
	if len(c.During) == HistoryLimit {
		copy(c.During[1:], c.During[2:])
		c.During = c.During[:HistoryLimit-1]
		c.Dropped++
	}
	c.During = append(c.During, r.Clone())
}

// AppendRecent retains the latest reports for the status endpoint and the
// pre-incident window. Each owner receives an independent copy of the report.
func AppendRecent(history []Report, r Report) []Report {
	if r.Status == "" {
		return history
	}
	if len(history) == HistoryLimit {
		copy(history, history[1:])
		history = history[:HistoryLimit-1]
	}
	return append(history, r.Clone())
}
