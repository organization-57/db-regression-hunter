// Package sqlstats derives interval metrics from pg_stat_statements counters.
// It does not collect SQL texts or infer regressions from cumulative averages.
package sqlstats

import (
	"math"
	"time"
)

// QueryID is a decimal string so JSON clients cannot lose bigint precision.
// All four fields belong to the PostgreSQL statistics entry identity.
type Identity struct {
	DatabaseID uint32 `json:"database_id"`
	UserID     uint32 `json:"user_id"`
	QueryID    string `json:"query_id"`
	TopLevel   bool   `json:"-"`
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
	Calls              int64      `json:"calls"`
	TotalExecMS        float64    `json:"total_exec_ms"`
	CallsPerSecond     float64    `json:"calls_per_second"`
	MeanExecMS         float64    `json:"mean_exec_ms"`
	SharedReadsPerCall float64    `json:"shared_reads_per_call"`
	SharedHitsPerCall  float64    `json:"shared_hits_per_call"`
	TempReadsPerCall   float64    `json:"temp_reads_per_call"`
	TempWritesPerCall  float64    `json:"temp_writes_per_call"`
	RowsPerCall        float64    `json:"rows_per_call"`
	Comparison         Comparison `json:"comparison"`
}

type Report struct {
	Available                 bool      `json:"available"`
	Status                    string    `json:"status"`
	Reason                    string    `json:"reason,omitempty"`
	From                      time.Time `json:"-"`
	At                        time.Time `json:"at"`
	IntervalSeconds           float64   `json:"interval_seconds"`
	ObservedStatements        int       `json:"observed_statements"`
	NewStatements             int       `json:"-"`
	ResetStatements           int       `json:"-"`
	MissingStatements         int       `json:"-"`
	ActiveStatements          int       `json:"-"`
	Queries                   []Query   `json:"-"`
	BaselinedStatements       int       `json:"baselined_statements"`
	AnalysisLimitedStatements int       `json:"analysis_limited_statements,omitempty"`
	PendingRegressions        int       `json:"pending_regressions,omitempty"`
	ActiveRegressions         int       `json:"active_regressions,omitempty"`
	RecoveringRegressions     int       `json:"recovering_regressions,omitempty"`
	UnknownRegressions        int       `json:"unknown_regressions,omitempty"`
	// Episodes supplies the detector with all updates for this interval.
	// Clone deliberately omits it from retained snapshots.
	Episodes []Regression `json:"-"`
}

// Clone retains only the public summary; samples and episodes belong to the detector.
func (r Report) Clone() Report {
	r.Queries = nil
	r.Episodes = nil
	return r
}

// Tracker is owned by the collection loop. Only adjacent complete snapshots
// from the same statistics generation can produce a valid interval.
type Tracker struct {
	MaxSampleGap time.Duration
	Regressor    *Regressor
	previous     *Snapshot
	entries      map[Identity]Counters
}

func (t *Tracker) Reset() {
	t.previous = nil
	t.entries = nil
	if t.Regressor != nil {
		t.Regressor.Interrupt("collection_failed")
	}
}

func (t *Tracker) finish(r Report, reason string) Report {
	if t.Regressor != nil {
		if reason != "" {
			t.Regressor.Interrupt(reason)
		}
		t.Regressor.summarize(&r, nil)
	}
	return r
}

func (t *Tracker) seed(s Snapshot) {
	t.entries = make(map[Identity]Counters, len(s.Entries))
	for _, entry := range s.Entries {
		t.entries[entry.Identity] = entry
	}
	s.Entries = nil
	t.previous = &s
}

func (t *Tracker) Observe(s Snapshot) Report {
	r := Report{At: s.At, Available: s.Available, ObservedStatements: len(s.Entries), Queries: []Query{}}
	if !s.Available || s.At.IsZero() {
		r.Available = false
		r.Status = "unavailable"
		r.Reason = s.Reason
		if r.Reason == "" {
			r.Reason = "invalid_sample"
		}
		t.Reset()
		return t.finish(r, r.Reason)
	}
	if t.previous == nil {
		t.seed(s)
		r.Status = "warming_up"
		return t.finish(r, "")
	}
	previous := t.previous
	if !s.At.After(previous.At) {
		r.Status = "stale"
		r.Reason = "non_monotonic_timestamp"
		return t.finish(r, "") // Do not replace the last usable sample with an old one.
	}
	duration := s.At.Sub(previous.At)
	if !s.ServerStartedAt.Equal(previous.ServerStartedAt) || !s.ResetAt.Equal(previous.ResetAt) || s.Deallocations != previous.Deallocations {
		t.seed(s)
		r.Status = "reset"
		r.Reason = "statistics_generation_changed"
		return t.finish(r, r.Reason)
	}
	if t.MaxSampleGap > 0 && duration > t.MaxSampleGap {
		t.seed(s)
		r.Status = "gap"
		r.Reason = "sampling_gap"
		return t.finish(r, r.Reason)
	}
	r.Status = "ready"
	r.From = previous.At
	r.IntervalSeconds = duration.Seconds()
	seen := make(map[Identity]bool, len(s.Entries))
	quality := make(map[Identity]string, len(s.Entries))
	for _, current := range s.Entries {
		seen[current.Identity] = true
		old, exists := t.entries[current.Identity]
		if !exists {
			quality[current.Identity] = "new_statement"
			r.NewStatements++
			continue
		}
		if !current.Since.Equal(old.Since) || !validDelta(old, current) {
			quality[current.Identity] = "entry_reset"
			r.ResetStatements++
			continue
		}
		calls := current.Calls - old.Calls
		if calls == 0 {
			quality[current.Identity] = "idle"
			continue
		}
		quality[current.Identity] = "valid"
		n := float64(calls)
		elapsed := current.TotalExecMS - old.TotalExecMS
		r.Queries = append(r.Queries, Query{
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
	if t.Regressor != nil {
		t.Regressor.analyze(&r, quality)
	}
	r.ActiveStatements = len(r.Queries)
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
