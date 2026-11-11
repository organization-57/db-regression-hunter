package sqlstats

import (
	"math"
	"sort"
	"time"
)

const maxTrackedQueries = 10000

// Comparison compares one interval with prior eligible intervals. A nil ratio
// means its denominator was zero, rather than an invented numerical factor.
type Comparison struct {
	State                  string   `json:"state"`
	BaselineIntervals      int      `json:"baseline_intervals"`
	BaselineCalls          int64    `json:"baseline_calls"`
	BaselineMeanExecMS     float64  `json:"baseline_mean_exec_ms"`
	BaselineCallsPerSecond float64  `json:"baseline_calls_per_second"`
	ThresholdMS            float64  `json:"threshold_ms"`
	ExecFactor             *float64 `json:"exec_factor,omitempty"`
	CallRateFactor         *float64 `json:"call_rate_factor,omitempty"`
	LoadIncreased          bool     `json:"load_increased"`
	Confirmations          int      `json:"confirmations"`
	RecoverySamples        int      `json:"recovery_samples"`
}

func (c Comparison) clone() Comparison {
	if c.ExecFactor != nil {
		v := *c.ExecFactor
		c.ExecFactor = &v
	}
	if c.CallRateFactor != nil {
		v := *c.CallRateFactor
		c.CallRateFactor = &v
	}
	return c
}

func (q Query) Clone() Query { q.Comparison = q.Comparison.clone(); return q }

type Regression struct {
	Identity
	StartedAt      time.Time  `json:"started_at"`
	DetectedAt     time.Time  `json:"detected_at"`
	LastObservedAt time.Time  `json:"last_observed_at"`
	Status         string     `json:"status"`
	Reason         string     `json:"reason,omitempty"`
	RecoveredAt    *time.Time `json:"recovered_at,omitempty"`
	Current        Query      `json:"current"`
}

func (r Regression) Clone() Regression {
	r.Current = r.Current.Clone()
	if r.RecoveredAt != nil {
		at := *r.RecoveredAt
		r.RecoveredAt = &at
	}
	return r
}

type referenceSample struct {
	calls           int64
	execMS, seconds float64
}

type queryBaseline struct {
	samples               []referenceSample
	streak, recovery      int
	started, lastEligible time.Time
	episode               *Regression
}

// Regressor belongs to Tracker. Active episodes retain their frozen reference
// across interruptions; only fresh, sufficiently populated intervals can prove
// recovery. Normal baselines expire after MaxIdle or an invalid statistics epoch.
type Regressor struct {
	size, confirm     int
	factor            float64
	minCalls          int64
	minIncreaseMS     float64
	MaxIdle           time.Duration
	RecoveryIntervals int
	states            map[Identity]*queryBaseline
}

func NewRegressor(size, confirm int, factor float64, minCalls int64, minIncreaseMS float64) *Regressor {
	return &Regressor{size: size, confirm: confirm, factor: factor, minCalls: minCalls, minIncreaseMS: minIncreaseMS, MaxIdle: 15 * time.Minute, RecoveryIntervals: confirm, states: make(map[Identity]*queryBaseline)}
}

func (d *Regressor) Interrupt(reason string) {
	for id, state := range d.states {
		if state.episode == nil {
			delete(d.states, id)
			continue
		}
		markUnknown(state, reason)
	}
}

func markUnknown(state *queryBaseline, reason string) {
	state.streak = 0
	state.recovery = 0
	state.started = time.Time{}
	if state.episode != nil {
		state.episode.Status = "unknown"
		state.episode.Reason = reason
	}
}

func (d *Regressor) comparison(state *queryBaseline, q Query) Comparison {
	c := Comparison{BaselineIntervals: len(state.samples)}
	var elapsed, seconds float64
	for _, sample := range state.samples {
		c.BaselineCalls += sample.calls
		elapsed += sample.execMS
		seconds += sample.seconds
	}
	if c.BaselineCalls > 0 {
		c.BaselineMeanExecMS = elapsed / float64(c.BaselineCalls)
	}
	if seconds > 0 {
		c.BaselineCallsPerSecond = float64(c.BaselineCalls) / seconds
	}
	c.ThresholdMS = math.Max(c.BaselineMeanExecMS*d.factor, c.BaselineMeanExecMS+d.minIncreaseMS)
	if c.BaselineMeanExecMS > 0 {
		factor := q.MeanExecMS / c.BaselineMeanExecMS
		c.ExecFactor = &factor
	}
	if c.BaselineCallsPerSecond > 0 {
		factor := q.CallsPerSecond / c.BaselineCallsPerSecond
		c.CallRateFactor = &factor
		c.LoadIncreased = factor >= d.factor
	}
	return c
}

func (d *Regressor) addNormal(state *queryBaseline, q Query, seconds float64, at time.Time) {
	if len(state.samples) == d.size {
		copy(state.samples, state.samples[1:])
		state.samples = state.samples[:d.size-1]
	}
	state.samples = append(state.samples, referenceSample{calls: q.Calls, execMS: q.TotalExecMS, seconds: seconds})
	state.lastEligible = at
}

// analyze processes all interval samples. Quality includes every observed entry,
// including idle, reset and newly seen SQL, so disappearance is never recovery.
func (d *Regressor) analyze(r *Report, quality map[Identity]string) {
	for id, state := range d.states {
		reason, seen := quality[id]
		if !seen {
			reason = "statement_missing"
		}
		if !seen || reason == "entry_reset" || reason == "new_statement" {
			if state.episode == nil {
				delete(d.states, id)
			} else {
				markUnknown(state, reason)
			}
		} else if reason == "idle" {
			markUnknown(state, "insufficient_calls")
		}
		if state.episode == nil && d.MaxIdle > 0 && !state.lastEligible.IsZero() && r.At.Sub(state.lastEligible) > d.MaxIdle {
			delete(d.states, id)
		}
	}
	var resolved []Regression
	for n := range r.Queries {
		q := &r.Queries[n]
		state := d.states[q.Identity]
		if q.Calls < d.minCalls {
			if state != nil {
				q.Comparison = d.comparison(state, *q)
				markUnknown(state, "insufficient_calls")
			}
			q.Comparison.State = "insufficient_calls"
			if state != nil && state.episode != nil {
				state.episode.Current = q.Clone()
				state.episode.LastObservedAt = r.At
			}
			continue
		}
		if state == nil {
			if len(d.states) >= maxTrackedQueries {
				q.Comparison.State = "capacity_exceeded"
				r.AnalysisLimitedStatements++
				continue
			}
			state = &queryBaseline{}
			d.states[q.Identity] = state
		}
		if len(state.samples) < d.size {
			d.addNormal(state, *q, r.IntervalSeconds, r.At)
			q.Comparison = d.comparison(state, *q)
			q.Comparison.State = "warming_up"
			continue
		}
		q.Comparison = d.comparison(state, *q)
		if q.MeanExecMS > q.Comparison.ThresholdMS {
			if state.streak == 0 {
				state.started = r.From
			}
			state.streak = min(state.streak+1, d.confirm)
			state.recovery = 0
			q.Comparison.State = "pending"
			q.Comparison.Confirmations = state.streak
			if state.episode != nil || state.streak >= d.confirm {
				q.Comparison.State = "active"
				if state.episode == nil {
					state.episode = &Regression{Identity: q.Identity, StartedAt: state.started, DetectedAt: r.At}
				}
				state.episode.Status = "active"
				state.episode.Reason = ""
				state.episode.Current = q.Clone()
				state.episode.LastObservedAt = r.At
			}
			// Freeze reference from the very first suspicious interval.
			continue
		}
		state.streak = 0
		state.started = time.Time{}
		q.Comparison.State = "normal"
		if state.episode != nil {
			state.recovery++
			q.Comparison.State = "recovering"
			q.Comparison.RecoverySamples = state.recovery
			state.episode.Status = "recovering"
			state.episode.Reason = ""
			if state.recovery >= d.RecoveryIntervals {
				q.Comparison.State = "resolved"
				at := r.At
				state.episode.Status = "resolved"
				state.episode.RecoveredAt = &at
			}
			state.episode.Current = q.Clone()
			state.episode.LastObservedAt = r.At
			if state.episode.Status != "resolved" {
				continue
			}
			resolved = append(resolved, state.episode.Clone())
			state.episode = nil
			state.recovery = 0
		}
		d.addNormal(state, *q, r.IntervalSeconds, r.At)
	}
	d.summarize(r, resolved)
}

func (d *Regressor) summarize(r *Report, resolved []Regression) {
	var episodes []Regression
	for _, state := range d.states {
		if len(state.samples) >= d.size {
			r.BaselinedStatements++
		}
		if state.streak > 0 && state.episode == nil {
			r.PendingRegressions++
		}
		if state.episode == nil {
			continue
		}
		e := state.episode
		if e.Status == "unknown" {
			r.UnknownRegressions++
		} else {
			r.ActiveRegressions++
			if e.Status == "recovering" {
				r.RecoveringRegressions++
			}
		}
		episodes = append(episodes, e.Clone())
	}
	episodes = append(episodes, resolved...)
	sort.Slice(episodes, func(i, j int) bool {
		a, b := episodes[i], episodes[j]
		rank := func(status string) int {
			switch status {
			case "active":
				return 0
			case "recovering":
				return 1
			case "unknown":
				return 2
			default:
				return 3
			}
		}
		if rank(a.Status) != rank(b.Status) {
			return rank(a.Status) < rank(b.Status)
		}
		if !a.DetectedAt.Equal(b.DetectedAt) {
			return a.DetectedAt.Before(b.DetectedAt)
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
	r.Episodes = episodes
}
