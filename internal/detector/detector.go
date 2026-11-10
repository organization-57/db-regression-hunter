package detector

import (
	"fmt"
	"math"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
)

const (
	Open       = "open"
	Recovering = "recovering"
	Resolved   = "resolved"
)

type Trigger struct {
	Metric    string  `json:"metric"`
	Observed  float64 `json:"observed"`
	Baseline  float64 `json:"baseline"`
	Threshold float64 `json:"threshold"`
}

type Blocker struct {
	PID    int     `json:"pid"`
	Chains [][]int `json:"chains"`
}

type Recovery struct {
	RequiredSamples    int  `json:"required_samples"`
	NormalSamples      int  `json:"normal_samples"`
	QueryAgeNormal     bool `json:"query_age_normal"`
	LockWaitersCleared bool `json:"lock_waiters_cleared"`
	GraphComplete      bool `json:"graph_complete"`
}

type Incident struct {
	ID                string                   `json:"id"`
	Status            string                   `json:"status"`
	StartedAt         time.Time                `json:"started_at"`
	DetectedAt        time.Time                `json:"detected_at"`
	UpdatedAt         time.Time                `json:"updated_at"`
	RecoveryStartedAt *time.Time               `json:"recovery_started_at,omitempty"`
	ResolvedAt        *time.Time               `json:"resolved_at,omitempty"`
	Finding           string                   `json:"finding"`
	Trigger           Trigger                  `json:"trigger"`
	PeakQuerySeconds  float64                  `json:"peak_query_seconds"`
	PeakLockWaiters   int                      `json:"peak_lock_waiters"`
	Blockers          []Blocker                `json:"blockers"`
	BlockingGraph     *collector.BlockingGraph `json:"blocking_graph,omitempty"`
	Recovery          Recovery                 `json:"recovery"`
	DataGaps          int                      `json:"data_gaps"`
	Notify            bool                     `json:"-"`
}

type Options struct {
	BaselineSamples, ConfirmSamples, RecoverySamples int
	Factor                                           float64
	MaxGap                                           time.Duration
}

// Detector belongs to the collection loop; returned reports are immutable copies.
// Observe returns updates for the same ID. Notify is true only at opening and resolution.
type Detector struct {
	options         Options
	samples         []float64
	streak          int
	started, lastAt time.Time
	current         *Incident
}

func New(options Options) *Detector { return &Detector{options: options} }

// Missing does not close an incident or infer recovery from absence of observations.
func (d *Detector) Missing(at time.Time) *Incident {
	d.streak = 0
	d.lastAt = time.Time{}
	if d.current == nil {
		d.samples = nil
		return nil
	}
	i := d.current
	i.DataGaps++
	i.UpdatedAt = at
	i.Status = Open
	i.RecoveryStartedAt = nil
	i.Recovery = Recovery{RequiredSamples: d.options.RecoverySamples}
	return d.update(false)
}

func (d *Detector) Observe(s collector.Snapshot) *Incident {
	if !d.lastAt.IsZero() && d.options.MaxGap > 0 && s.At.Sub(d.lastAt) > d.options.MaxGap {
		d.Missing(s.At)
	}
	d.lastAt = s.At
	if d.current != nil {
		return d.observeActive(s)
	}
	if len(d.samples) < d.options.BaselineSamples {
		d.samples = append(d.samples, s.OldestQuerySeconds)
		return nil
	}
	var sum float64
	for _, v := range d.samples {
		sum += v
	}
	baseline := sum / float64(len(d.samples))
	threshold := math.Max(1, baseline*d.options.Factor)
	if s.OldestQuerySeconds <= threshold {
		d.streak = 0
		copy(d.samples, d.samples[1:])
		d.samples[len(d.samples)-1] = s.OldestQuerySeconds
		return nil
	}
	if d.streak == 0 {
		d.started = s.At
	}
	d.streak++
	if d.streak < d.options.ConfirmSamples {
		return nil
	}
	d.current = &Incident{
		ID: fmt.Sprintf("%d", s.At.UnixNano()), Status: Open, StartedAt: d.started, DetectedAt: s.At, UpdatedAt: s.At,
		Trigger:  Trigger{Metric: "oldest_query_seconds", Observed: s.OldestQuerySeconds, Baseline: baseline, Threshold: threshold},
		Finding:  "query_age_regression",
		Blockers: []Blocker{}, Recovery: Recovery{RequiredSamples: d.options.RecoverySamples},
	}
	d.enrich(s)
	d.current.observeRecoveryConditions(s)
	return d.update(true)
}

func (d *Detector) observeActive(s collector.Snapshot) *Incident {
	i := d.current
	i.UpdatedAt = s.At
	d.enrich(s)
	i.observeRecoveryConditions(s)
	normal := i.Recovery.QueryAgeNormal && i.Recovery.LockWaitersCleared && i.Recovery.GraphComplete
	if !normal {
		i.Status = Open
		i.Recovery.NormalSamples = 0
		i.RecoveryStartedAt = nil
		return d.update(false)
	}
	if i.Recovery.NormalSamples == 0 {
		at := s.At
		i.RecoveryStartedAt = &at
	}
	i.Recovery.NormalSamples++
	i.Status = Recovering
	if i.Recovery.NormalSamples < d.options.RecoverySamples {
		return d.update(false)
	}
	i.Status = Resolved
	at := s.At
	i.ResolvedAt = &at
	result := d.update(true)
	d.current = nil
	d.streak = 0
	// Freeze the original normal baseline through the episode and recovery.
	return result
}

func (i *Incident) observeRecoveryConditions(s collector.Snapshot) {
	i.Recovery.QueryAgeNormal = s.OldestQuerySeconds <= i.Trigger.Threshold
	i.Recovery.LockWaitersCleared = s.LockWaiters == 0 && s.BlockingGraph != nil && len(s.BlockingGraph.Nodes) == 0
	i.Recovery.GraphComplete = s.BlockingGraph != nil && s.BlockingGraph.Complete
}

func (d *Detector) enrich(s collector.Snapshot) {
	i := d.current
	if s.OldestQuerySeconds > i.PeakQuerySeconds {
		i.PeakQuerySeconds = s.OldestQuerySeconds
	}
	if s.LockWaiters > i.PeakLockWaiters {
		i.PeakLockWaiters = s.LockWaiters
	}
	if s.LockWaiters > 0 && len(i.Blockers) == 0 {
		i.Finding = "lock_wait"
	}
	roots := findBlockers(s.BlockingGraph)
	if len(roots) > 0 {
		i.Blockers = roots
		// Keep a bounded observed graph even after blocking sessions disappear.
		i.BlockingGraph = collector.CloneGraph(s.BlockingGraph)
		i.Finding = "lock_contention"
	} else if i.BlockingGraph == nil && s.BlockingGraph != nil && len(s.BlockingGraph.Nodes) > 0 {
		i.BlockingGraph = collector.CloneGraph(s.BlockingGraph)
	}
}

func (d *Detector) update(notify bool) *Incident {
	result := CloneIncident(*d.current)
	result.Notify = notify
	return &result
}
