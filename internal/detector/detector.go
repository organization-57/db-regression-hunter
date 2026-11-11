package detector

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

const (
	Open       = "open"
	Recovering = "recovering"
	Resolved   = "resolved"
)

type Finding string

const (
	FindingQueryAgeRegression     Finding = "query_age_regression"
	FindingLockWait               Finding = "lock_wait"
	FindingLockContention         Finding = "lock_contention"
	FindingActiveSessionsSurge    Finding = "active_sessions_surge"
	FindingTempFileGrowth         Finding = "temp_file_growth"
	FindingDeadlock               Finding = "deadlock"
	FindingSQLExecutionRegression Finding = "sql_execution_regression"
	FindingIdleInTransaction      Finding = "idle_in_transaction"
)

type Trigger struct {
	Metric          string  `json:"metric"`
	Observed        float64 `json:"observed"`
	Baseline        float64 `json:"baseline"`
	Threshold       float64 `json:"threshold"`
	IntervalSeconds float64 `json:"interval_seconds,omitempty"`
}

type Blocker struct {
	PID int `json:"pid"`
}

type Recovery struct {
	RequiredSamples int `json:"required_samples"`
	NormalSamples   int `json:"normal_samples"`
}

type Incident struct {
	ID                string                   `json:"id"`
	Status            string                   `json:"status"`
	StartedAt         time.Time                `json:"started_at"`
	DetectedAt        time.Time                `json:"detected_at"`
	UpdatedAt         time.Time                `json:"updated_at"`
	RecoveryStartedAt *time.Time               `json:"recovery_started_at,omitempty"`
	ResolvedAt        *time.Time               `json:"resolved_at,omitempty"`
	Findings          []Finding                `json:"findings"`
	Trigger           Trigger                  `json:"trigger"`
	Peak              float64                  `json:"peak"`
	Blockers          []Blocker                `json:"blockers,omitempty"`
	BlockingGraph     *collector.BlockingGraph `json:"blocking_graph,omitempty"`
	Recovery          Recovery                 `json:"recovery"`
	DataGaps          int                      `json:"data_gaps"`
	Notify            bool                     `json:"-"`
	SQLRegression     *SQLRegression           `json:"sql_regression,omitempty"`
	Tables            json.RawMessage          `json:"tables,omitempty"`
	Settings          json.RawMessage          `json:"settings,omitempty"`
	Queries           []QueryEvidence          `json:"queries,omitempty"`
}

type SQLRegression struct {
	sqlstats.Identity
	Status                 string    `json:"status"`
	Reason                 string    `json:"reason,omitempty"`
	LastObservedAt         time.Time `json:"last_observed_at"`
	Calls                  int64     `json:"calls"`
	MeanExecMS             float64   `json:"mean_exec_ms"`
	CallsPerSecond         float64   `json:"calls_per_second"`
	BaselineCallsPerSecond float64   `json:"baseline_calls_per_second"`
	SharedReadsPerCall     float64   `json:"shared_reads_per_call"`
	SharedHitsPerCall      float64   `json:"shared_hits_per_call"`
	TempReadsPerCall       float64   `json:"temp_reads_per_call"`
	TempWritesPerCall      float64   `json:"temp_writes_per_call"`
	RowsPerCall            float64   `json:"rows_per_call"`
}

type QueryEvidence struct {
	Role string `json:"role"`
	collector.QueryTarget
	Details json.RawMessage `json:"details"`
}

func (i Incident) HasFinding(f Finding) bool { return slices.Contains(i.Findings, f) }

func (i *Incident) addFinding(f Finding) {
	if !i.HasFinding(f) {
		i.Findings = append(i.Findings, f)
	}
}

type Options struct {
	BaselineSamples, ConfirmSamples, RecoverySamples int
	Factor                                           float64
	MaxGap                                           time.Duration
}

// Each metric has its own baseline and episode; only the collection loop owns them.
type signal struct {
	metric  string
	finding Finding
	floor   float64
	event   bool
	samples []float64
	streak  int
	started time.Time
	current *Incident
}

type Detector struct {
	incidentSequence uint64
	options          Options
	signals          []signal
	previous         *collector.Snapshot // One counter observation, never a raw history buffer.
	sqlIncidents     map[sqlstats.Identity]*Incident
}

// nextIncidentID is shared by every signal and SQL episode in this detector.
// Like the in-memory incident history, the sequence resets on restart.
func (d *Detector) nextIncidentID() string {
	d.incidentSequence++
	return strconv.FormatUint(d.incidentSequence, 10)
}

func New(options Options) *Detector {
	return &Detector{options: options, sqlIncidents: make(map[sqlstats.Identity]*Incident), signals: []signal{
		{metric: "oldest_query_seconds", finding: FindingQueryAgeRegression, floor: 1},
		{metric: "active_sessions", finding: FindingActiveSessionsSurge, floor: 4},
		{metric: "temp_bytes_per_second", finding: FindingTempFileGrowth, floor: 64 * 1024},
		{metric: "deadlocks_delta", finding: FindingDeadlock, event: true},
	}}
}

// Missing preserves open episodes but restarts confirmation and counter intervals.
func (d *Detector) Missing(at time.Time) []*Incident {
	d.previous = nil
	updates := d.missingSQL(at)
	for n := range d.signals {
		r := &d.signals[n]
		r.streak = 0
		if r.current == nil {
			r.samples = nil
			continue
		}
		i := r.current
		i.DataGaps++
		i.UpdatedAt = at
		i.Status = Open
		i.RecoveryStartedAt = nil
		i.Recovery.NormalSamples = 0
		updates = append(updates, r.update(false))
	}
	return updates
}

func (d *Detector) Observe(s collector.Snapshot) []*Incident {
	previous := d.previous
	var updates []*Incident
	interval := 0.0
	if previous != nil {
		interval = s.At.Sub(previous.At).Seconds()
		// Never compare counters across missing observations, resets, restarts or clock reversal.
		if interval <= 0 || (d.options.MaxGap > 0 && s.At.Sub(previous.At) > d.options.MaxGap) ||
			!s.PostmasterStart.Equal(previous.PostmasterStart) || !sameTime(s.StatsReset, previous.StatsReset) ||
			s.TempBytes < previous.TempBytes || s.Deadlocks < previous.Deadlocks {
			d.Missing(s.At)
			previous = nil
			interval = 0
		}
	}
	for n := range d.signals {
		r := &d.signals[n]
		value, window := 0.0, 0.0
		switch r.metric {
		case "oldest_query_seconds":
			value = s.OldestQuerySeconds
		case "active_sessions":
			value = float64(s.Active)
		case "temp_bytes_per_second", "deadlocks_delta":
			if previous == nil {
				if r.current != nil {
					updates = append(updates, r.update(false))
				}
				continue
			}
			window = interval
			if r.metric == "temp_bytes_per_second" {
				value = float64(s.TempBytes-previous.TempBytes) / interval
			} else {
				value = float64(s.Deadlocks - previous.Deadlocks)
			}
		default:
			continue
		}
		if i := r.observe(s, value, window, d.options, d.nextIncidentID); i != nil {
			updates = append(updates, i)
		}
	}
	updates = append(updates, d.observeSQL(s.SQL)...)
	compact := s
	compact.BlockingGraph = nil
	compact.SQL = sqlstats.Report{}
	compact.Statements = sqlstats.Snapshot{}
	d.previous = &compact
	return updates
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func (r *signal) observe(s collector.Snapshot, value, interval float64, options Options, nextID func() string) *Incident {
	if r.current == nil {
		baseline, threshold := 0.0, 0.0
		if !r.event {
			if len(r.samples) < options.BaselineSamples {
				r.samples = append(r.samples, value)
				return nil
			}
			for _, v := range r.samples {
				baseline += v
			}
			baseline /= float64(len(r.samples))
			threshold = math.Max(r.floor, baseline*options.Factor)
		}
		if value <= threshold {
			r.streak = 0
			if !r.event {
				copy(r.samples, r.samples[1:])
				r.samples[len(r.samples)-1] = value
			}
			return nil
		}
		if r.streak == 0 {
			r.started = s.At
			if interval > 0 {
				r.started = s.At.Add(-time.Duration(interval * float64(time.Second)))
			}
		}
		r.streak++
		if !r.event && r.streak < options.ConfirmSamples {
			return nil
		}
		r.current = &Incident{
			ID: nextID(), Status: Open, StartedAt: r.started, DetectedAt: s.At, UpdatedAt: s.At,
			Findings: []Finding{r.finding}, Trigger: Trigger{Metric: r.metric, Observed: value, Baseline: baseline, Threshold: threshold, IntervalSeconds: interval},
			Peak: value, Recovery: Recovery{RequiredSamples: options.RecoverySamples},
		}
		r.enrich(s)
		return r.update(true)
	}
	i := r.current
	i.UpdatedAt = s.At
	i.Peak = math.Max(i.Peak, value)
	r.enrich(s)
	normal := value <= i.Trigger.Threshold
	if r.metric == "oldest_query_seconds" {
		normal = normal && s.LockWaiters == 0 && s.BlockingGraph != nil && s.BlockingGraph.Complete && len(s.BlockingGraph.Nodes) == 0
	}
	if !normal {
		i.Status = Open
		i.Recovery.NormalSamples = 0
		i.RecoveryStartedAt = nil
		return r.update(false)
	}
	if i.Recovery.NormalSamples == 0 {
		at := s.At
		i.RecoveryStartedAt = &at
	}
	i.Recovery.NormalSamples++
	i.Status = Recovering
	if i.Recovery.NormalSamples < options.RecoverySamples {
		return r.update(false)
	}
	i.Status = Resolved
	at := s.At
	i.ResolvedAt = &at
	result := r.update(true)
	r.current = nil
	r.streak = 0
	return result
}

func (r *signal) enrich(s collector.Snapshot) {
	if r.metric != "oldest_query_seconds" {
		return
	}
	i := r.current
	if s.LockWaiters > 0 {
		i.addFinding(FindingLockWait)
	}
	roots := findBlockers(s.BlockingGraph)
	if len(roots) > 0 {
		i.addFinding(FindingLockWait)
		i.Blockers = roots
		i.BlockingGraph = collector.CloneGraph(s.BlockingGraph)
		i.addFinding(FindingLockContention)
		for _, root := range roots {
			for _, node := range s.BlockingGraph.Nodes {
				if node.PID == root.PID && (node.State == "idle in transaction" || node.State == "idle in transaction (aborted)") {
					i.addFinding(FindingIdleInTransaction)
				}
			}
		}
	} else if i.BlockingGraph == nil && s.BlockingGraph != nil && len(s.BlockingGraph.Nodes) > 0 {
		i.BlockingGraph = collector.CloneGraph(s.BlockingGraph)
	}
}

func (r *signal) update(notify bool) *Incident {
	result := CloneIncident(*r.current)
	result.Notify = notify
	return &result
}
