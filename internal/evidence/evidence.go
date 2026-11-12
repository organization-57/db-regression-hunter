package evidence

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

const (
	Schema          = "hunter.evidence/v5"
	baselineSamples = 30
	maxLocks        = 8
	maxStatements   = 5
	maxSessions     = 5
	maxIncidents    = 8
	maxText         = 64
	maxStep         = time.Minute
)

type Package struct {
	Schema            string            `json:"schema"`
	Incidents         []Incident        `json:"incidents"`
	BaselineWindow    Window            `json:"baseline_window"`
	IncidentWindow    Window            `json:"incident_window"`
	Metrics           []Metric          `json:"metrics"`
	Locks             []Lock            `json:"locks,omitempty"`
	LockGraphComplete *bool             `json:"lock_graph_complete,omitempty"`
	LockGraphCurrent  bool              `json:"lock_graph_current,omitempty"`
	Statements        []Statement       `json:"regressed_statements,omitempty"`
	Sessions          []Session         `json:"long_running_sessions,omitempty"`
	Tables            []Table           `json:"tables,omitempty"`
	Settings          map[string]string `json:"settings,omitempty"`
	SQLNames          string            `json:"sql_names,omitempty"`
	SQLStatistics     string            `json:"sql_statistics"`
	MissingSources    []string          `json:"missing_sources"`
}

type Window struct {
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Samples int       `json:"samples"`
}

type Incident struct {
	ID              string    `json:"id"`
	IncidentID      string    `json:"incident_id"`
	Findings        []string  `json:"findings"`
	Status          string    `json:"status"`
	StartedAt       time.Time `json:"started_at"`
	Metric          string    `json:"metric"`
	Observed        float64   `json:"observed"`
	Baseline        float64   `json:"baseline"`
	Threshold       float64   `json:"threshold"`
	Peak            float64   `json:"peak"`
	IntervalSeconds float64   `json:"interval_seconds,omitempty"`
	Statement       string    `json:"statement,omitempty"`
}

type Change struct {
	Baseline *float64 `json:"baseline"`
	Incident *float64 `json:"incident"`
}

type Metric struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Unit string   `json:"unit"`
	Peak *float64 `json:"incident_peak,omitempty"`
	Change
}

type Lock struct {
	ID                    string         `json:"id"`
	BlockingPID           int            `json:"blocking_pid"`
	Root                  bool           `json:"root"`
	BlockingApplication   string         `json:"blocking_application"`
	BlockingState         string         `json:"blocking_state"`
	BlockingWaitEvent     string         `json:"blocking_wait_event,omitempty"`
	BlockingQuery         string         `json:"blocking_last_query,omitempty"`
	QuerySource           string         `json:"blocking_query_source,omitempty"`
	HeldLocks             []HeldLock     `json:"blocking_held_locks,omitempty"`
	NamesFrom             string         `json:"names_from,omitempty"`
	BackendStart          *time.Time     `json:"backend_start,omitempty"`
	QueryStart            *time.Time     `json:"query_start,omitempty"`
	TransactionStart      *time.Time     `json:"transaction_start,omitempty"`
	ObservedAt            time.Time      `json:"observed_at"`
	QueryObservedAt       *time.Time     `json:"query_observed_at,omitempty"`
	Plan                  map[string]any `json:"plan,omitempty"`
	PlanKind              string         `json:"plan_kind,omitempty"`
	TableScope            string         `json:"table_scope,omitempty"`
	TransactionAgeSeconds float64        `json:"blocking_transaction_age_seconds"`
	BlockedPIDs           []int          `json:"blocked_pids"`
	BlockedTotal          int            `json:"blocked_total_through_chain"`
	WaiterWaitEvents      []string       `json:"waiter_wait_events"`
	MaxWaiterQueryAge     float64        `json:"max_waiter_query_age_seconds"`
}

type Session struct {
	ID               string     `json:"id"`
	PID              int        `json:"pid"`
	Application      string     `json:"application"`
	State            string     `json:"state"`
	WaitEvent        string     `json:"wait_event,omitempty"`
	BackendStart     *time.Time `json:"backend_start,omitempty"`
	QueryStart       *time.Time `json:"query_start,omitempty"`
	TransactionStart *time.Time `json:"transaction_start,omitempty"`
	ObservedAt       time.Time  `json:"observed_at"`
	QueryAgeSeconds  float64    `json:"query_age_seconds"`
	TransactionAge   float64    `json:"transaction_age_seconds"`
}

type Statement struct {
	ID                 string         `json:"id"`
	QueryID            string         `json:"queryid"`
	Status             string         `json:"status"`
	MeanExecMS         Change         `json:"mean_exec_ms"`
	CallsPerSecond     Change         `json:"calls_per_second"`
	SharedReadsPerCall float64        `json:"shared_reads_per_call"`
	SharedHitsPerCall  float64        `json:"shared_hits_per_call"`
	TempWritesPerCall  float64        `json:"temp_writes_per_call"`
	RowsPerCall        float64        `json:"rows_per_call"`
	Query              string         `json:"query,omitempty"`
	Plan               map[string]any `json:"plan,omitempty"`
	PlanKind           string         `json:"plan_kind,omitempty"`
	QuerySource        string         `json:"query_source,omitempty"`
	ObservedAt         *time.Time     `json:"observed_at,omitempty"`
	NamesFrom          string         `json:"names_from,omitempty"`
}

type History struct {
	size     int
	snaps    []collector.Snapshot
	incident []bool
}

func NewHistory(size int) *History { return &History{size: max(2, size)} }

func (h *History) Add(s collector.Snapshot, duringIncident bool) {
	s.BlockingGraph, s.SQL, s.Statements = nil, sqlstats.Report{}, sqlstats.Snapshot{}
	h.snaps = append(h.snaps, collector.CloneSnapshot(s))
	h.incident = append(h.incident, duringIncident)
	if len(h.snaps) > h.size {
		h.snaps = append([]collector.Snapshot{}, h.snaps[len(h.snaps)-h.size:]...)
		h.incident = append([]bool{}, h.incident[len(h.incident)-h.size:]...)
	}
}

var findingOrder = map[detector.Finding]int{
	detector.FindingLockContention: 0, detector.FindingIdleInTransaction: 0, detector.FindingLockWait: 1, detector.FindingDeadlock: 2,
	detector.FindingTempFileGrowth: 3, detector.FindingActiveSessionsSurge: 4, detector.FindingQueryAgeRegression: 5, detector.FindingSQLExecutionRegression: 6,
}

func rank(i detector.Incident) int {
	best := len(findingOrder)
	for _, f := range i.Findings {
		if r, ok := findingOrder[f]; ok && r < best {
			best = r
		}
	}
	return best
}

func Build(incidents []detector.Incident, h *History, current collector.Snapshot) Package {
	p := Package{Schema: Schema, MissingSources: []string{}}
	incidents = append([]detector.Incident{}, incidents...)
	sort.SliceStable(incidents, func(a, b int) bool {
		if rank(incidents[a]) != rank(incidents[b]) {
			return rank(incidents[a]) < rank(incidents[b])
		}
		return incidents[a].StartedAt.Before(incidents[b].StartedAt)
	})
	if len(incidents) > maxIncidents {
		incidents = incidents[:maxIncidents]
	}
	var start time.Time
	for _, i := range incidents {
		if start.IsZero() || i.StartedAt.Before(start) {
			start = i.StartedAt
		}
	}
	var before, during series
	for n, s := range h.snaps {
		switch {
		case !s.At.Before(start):
			during.add(h, n)
		case !h.incident[n]:
			before.add(h, n)
		}
	}
	before = before.last(baselineSamples)
	p.BaselineWindow, p.IncidentWindow = before.window(), during.window()
	p.addMetrics(before, during)
	gaps := 0
	var stale *detector.Incident
	for n, i := range incidents {
		gaps += i.DataGaps
		e := Incident{ID: fmt.Sprintf("I%d", len(p.Incidents)+1), IncidentID: i.ID, Status: i.Status, StartedAt: i.StartedAt,
			Metric: i.Trigger.Metric, Observed: value(i.Trigger.Observed), Baseline: value(i.Trigger.Baseline), Threshold: value(i.Trigger.Threshold),
			Peak: value(i.Peak), IntervalSeconds: value(i.Trigger.IntervalSeconds)}
		for _, f := range i.Findings {
			e.Findings = append(e.Findings, string(f))
		}
		if i.SQLRegression != nil && len(p.Statements) < maxStatements {
			e.Statement = p.addStatement(i, e.ID)
		}
		p.Incidents = append(p.Incidents, e)
		if stale == nil && i.BlockingGraph != nil {
			stale = &incidents[n]
		}
	}
	switch {
	case current.BlockingGraph != nil && len(current.BlockingGraph.Nodes) > 0:
		p.addLocks(current.BlockingGraph, true)
	case stale != nil:
		p.addLocks(stale.BlockingGraph, false)
	}
	p.addQueryContext(incidents)
	p.SQLStatistics = sqlStatus(current.SQL)
	p.addMissing(len(before.snaps), gaps)
	return p
}

type series struct {
	snaps  []collector.Snapshot
	linked []bool
	index  []int
}

func (s *series) add(h *History, n int) {
	linked := len(s.index) > 0 && s.index[len(s.index)-1] == n-1 && h.snaps[n].At.Sub(h.snaps[n-1].At) <= maxStep
	s.snaps, s.linked, s.index = append(s.snaps, h.snaps[n]), append(s.linked, linked), append(s.index, n)
}

func (s series) last(n int) series {
	if len(s.snaps) <= n {
		return s
	}
	k := len(s.snaps) - n
	s.snaps, s.linked, s.index = s.snaps[k:], append([]bool{false}, s.linked[k+1:]...), s.index[k:]
	return s
}

func (s series) window() Window {
	if len(s.snaps) == 0 {
		return Window{}
	}
	return Window{From: s.snaps[0].At, To: s.snaps[len(s.snaps)-1].At, Samples: len(s.snaps)}
}

func sqlStatus(r sqlstats.Report) string {
	switch {
	case r.Status == "":
		return "not collected"
	case !r.Available:
		return "unavailable: " + r.Reason
	case r.Reason != "":
		return r.Status + ": " + r.Reason
	}
	return r.Status
}

type gauge struct {
	name, unit string
	value      func(collector.Snapshot) float64
}

type counter struct {
	name, unit string
	value      func(collector.Snapshot) int64
}

var gauges = []gauge{
	{"oldest_active_query_age", "s", func(s collector.Snapshot) float64 { return s.OldestQuerySeconds }},
	{"active_sessions", "sessions", func(s collector.Snapshot) float64 { return float64(s.Active) }},
	{"lock_waiting_sessions", "sessions", func(s collector.Snapshot) float64 { return float64(s.LockWaiters) }},
}

var counters = []counter{
	{"commits_per_second", "tx/s", func(s collector.Snapshot) int64 { return s.Commits }},
	{"rollbacks_per_second", "tx/s", func(s collector.Snapshot) int64 { return s.Rollbacks }},
	{"deadlocks_per_second", "1/s", func(s collector.Snapshot) int64 { return s.Deadlocks }},
	{"blocks_read_per_second", "blocks/s", func(s collector.Snapshot) int64 { return s.BlocksRead }},
	{"temp_bytes_per_second", "bytes/s", func(s collector.Snapshot) int64 { return s.TempBytes }},
}

func (p *Package) metric(name, unit string, c Change, peak *float64) {
	p.Metrics = append(p.Metrics, Metric{ID: fmt.Sprintf("M%d", len(p.Metrics)+1), Name: name, Unit: unit, Change: c, Peak: peak})
}

func (p *Package) addMetrics(before, during series) {
	for _, g := range gauges {
		p.metric(g.name, g.unit, Change{mean(before.snaps, g.value), mean(during.snaps, g.value)}, maximum(during.snaps, g.value))
	}
	for _, c := range counters {
		p.metric(c.name, c.unit, Change{rate(before, c.value), rate(during, c.value)}, nil)
	}
	p.metric("cache_hit_ratio", "%", Change{hitRatio(before), hitRatio(during)}, nil)
}

func mean(snaps []collector.Snapshot, f func(collector.Snapshot) float64) *float64 {
	if len(snaps) == 0 {
		return nil
	}
	var sum float64
	for _, s := range snaps {
		sum += f(s)
	}
	return round(sum / float64(len(snaps)))
}

func maximum(snaps []collector.Snapshot, f func(collector.Snapshot) float64) *float64 {
	if len(snaps) == 0 {
		return nil
	}
	v := math.Inf(-1)
	for _, s := range snaps {
		v = math.Max(v, f(s))
	}
	return round(v)
}

func rate(s series, f func(collector.Snapshot) int64) *float64 {
	var delta, seconds float64
	for n := 1; n < len(s.snaps); n++ {
		d, dt := f(s.snaps[n])-f(s.snaps[n-1]), s.snaps[n].At.Sub(s.snaps[n-1].At).Seconds()
		if !s.linked[n] || d < 0 || dt <= 0 {
			continue
		}
		delta += float64(d)
		seconds += dt
	}
	if seconds == 0 {
		return nil
	}
	return round(delta / seconds)
}

func hitRatio(s series) *float64 {
	var hit, read float64
	for n := 1; n < len(s.snaps); n++ {
		dh, dr := s.snaps[n].BlocksHit-s.snaps[n-1].BlocksHit, s.snaps[n].BlocksRead-s.snaps[n-1].BlocksRead
		if !s.linked[n] || dh < 0 || dr < 0 {
			continue
		}
		hit += float64(dh)
		read += float64(dr)
	}
	if hit+read == 0 {
		return nil
	}
	return round(hit / (hit + read) * 100)
}

func round(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	digits := 3.0
	if a := math.Abs(v); a >= 1 {
		digits = math.Max(0, 3-math.Floor(math.Log10(a))-1)
	}
	scale := math.Pow(10, digits)
	r := math.Round(v*scale) / scale
	return &r
}

func value(v float64) float64 {
	if r := round(v); r != nil {
		return *r
	}
	return 0
}

func (p *Package) addStatement(i detector.Incident, incident string) string {
	r := i.SQLRegression
	s := Statement{ID: fmt.Sprintf("Q%d", len(p.Statements)+1), QueryID: r.QueryID, Status: r.Status,
		MeanExecMS:         Change{round(i.Trigger.Baseline), round(r.MeanExecMS)},
		CallsPerSecond:     Change{round(r.BaselineCallsPerSecond), round(r.CallsPerSecond)},
		SharedReadsPerCall: value(r.SharedReadsPerCall), SharedHitsPerCall: value(r.SharedHitsPerCall),
		TempWritesPerCall: value(r.TempWritesPerCall), RowsPerCall: value(r.RowsPerCall),
	}
	for _, q := range i.Queries {
		if d, ok := parseDetails(q); ok && q.Role == "regressed" {
			s.Query, s.Plan, s.NamesFrom = d.SQL, d.Plan, incident
			s.PlanKind, s.QuerySource, s.ObservedAt = d.PlanKind, d.QuerySource, &d.At
		}
	}
	p.Statements = append(p.Statements, s)
	return s.ID
}

func (p *Package) addLocks(g *collector.BlockingGraph, current bool) {
	complete := g.Complete
	p.LockGraphComplete, p.LockGraphCurrent = &complete, current
	nodes := map[int]collector.Session{}
	children := map[int][]int{}
	for _, s := range g.Nodes {
		nodes[s.PID] = s
		for _, b := range s.BlockedBy {
			children[b] = append(children[b], s.PID)
		}
	}
	var roots, rest []int
	for pid := range children {
		if n, ok := nodes[pid]; ok && len(n.BlockedBy) == 0 {
			roots = append(roots, pid)
		} else {
			rest = append(rest, pid)
		}
	}
	sort.Ints(roots)
	sort.Ints(rest)
	p.Locks = []Lock{}
	for n, pid := range append(roots, rest...) {
		if len(p.Locks) == maxLocks {
			break
		}
		blocked := append([]int{}, children[pid]...)
		sort.Ints(blocked)
		s := nodes[pid]
		observed := s.ObservedAt
		if observed.IsZero() {
			observed = g.At
		}
		l := Lock{ID: fmt.Sprintf("L%d", len(p.Locks)+1), BlockingPID: pid, Root: n < len(roots), BlockingApplication: s.Application,
			BlockingState: Clean(s.State), BackendStart: s.BackendStart, QueryStart: s.QueryStart, TransactionStart: s.TransactionStart, ObservedAt: observed, TransactionAgeSeconds: value(s.TransactionAgeSeconds), BlockedPIDs: blocked, BlockedTotal: downstream(pid, children)}
		if s.WaitEventType != "" {
			l.BlockingWaitEvent = Clean(s.WaitEventType + ":" + s.WaitEvent)
		}
		events := map[string]bool{}
		for _, c := range blocked {
			w := nodes[c]
			if w.WaitEventType != "" {
				events[Clean(w.WaitEventType+":"+w.WaitEvent)] = true
			}
			l.MaxWaiterQueryAge = math.Max(l.MaxWaiterQueryAge, w.QueryAgeSeconds)
		}
		l.MaxWaiterQueryAge = value(l.MaxWaiterQueryAge)
		for e := range events {
			l.WaiterWaitEvents = append(l.WaiterWaitEvents, e)
		}
		sort.Strings(l.WaiterWaitEvents)
		p.Locks = append(p.Locks, l)
	}
}

func downstream(root int, children map[int][]int) int {
	seen := map[int]bool{root: true}
	queue := []int{root}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, c := range children[pid] {
			if !seen[c] {
				seen[c] = true
				queue = append(queue, c)
			}
		}
	}
	return len(seen) - 1
}

func Clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxText {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune(" _.:-/@", r):
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func (p *Package) addMissing(baseline, gaps int) {
	p.MissingSources = append(p.MissingSources,
		"application metrics (request rate, errors, latency) are not connected",
		"host metrics (CPU, disk I/O) are not connected",
		"deploy, DDL and configuration change events are not connected")
	if p.SQLStatistics != "ready" {
		p.MissingSources = append(p.MissingSources, "per-statement statistics (pg_stat_statements) state: "+p.SQLStatistics)
	}
	if p.LockGraphComplete != nil && !*p.LockGraphComplete {
		p.MissingSources = append(p.MissingSources, "blocking graph is incomplete")
	}
	if gaps > 0 {
		p.MissingSources = append(p.MissingSources, fmt.Sprintf("%d collection gaps during the incidents", gaps))
	}
	if baseline < 5 {
		p.MissingSources = append(p.MissingSources, fmt.Sprintf("baseline window has only %d snapshots", baseline))
	}
	if len(p.Locks) > 0 && !p.LockGraphCurrent {
		p.MissingSources = append(p.MissingSources, "no lock waits at analysis time; locks are from the last graph of the incident")
	}
}

func (p Package) IDs() map[string]bool {
	ids := map[string]bool{}
	for _, i := range p.Incidents {
		ids[i.ID] = true
	}
	for _, m := range p.Metrics {
		ids[m.ID] = true
	}
	for _, l := range p.Locks {
		ids[l.ID] = true
	}
	for _, s := range p.Statements {
		ids[s.ID] = true
	}
	for _, s := range p.Sessions {
		ids[s.ID] = true
	}
	for _, t := range p.Tables {
		ids[t.ID] = true
	}
	return ids
}

func (p *Package) AddSessions(sessions []collector.Session) {
	for _, s := range sessions {
		if len(p.Sessions) == maxSessions {
			return
		}
		e := Session{ID: fmt.Sprintf("S%d", len(p.Sessions)+1), PID: s.PID, Application: s.Application, BackendStart: s.BackendStart, QueryStart: s.QueryStart, TransactionStart: s.TransactionStart, ObservedAt: s.ObservedAt, State: Clean(s.State),
			QueryAgeSeconds: value(s.QueryAgeSeconds), TransactionAge: value(s.TransactionAgeSeconds)}
		if s.WaitEventType != "" {
			e.WaitEvent = Clean(s.WaitEventType + ":" + s.WaitEvent)
		}
		p.Sessions = append(p.Sessions, e)
	}
}

func (p Package) IncidentIDs() []string {
	ids := make([]string, 0, len(p.Incidents))
	for _, i := range p.Incidents {
		ids = append(ids, i.IncidentID)
	}
	return ids
}

func (p Package) RootPIDs() map[string]bool {
	pids := map[string]bool{}
	if p.LockGraphComplete == nil || !*p.LockGraphComplete || !p.LockGraphCurrent {
		return pids
	}
	for _, l := range p.Locks {
		if l.Root {
			pids[fmt.Sprint(l.BlockingPID)] = true
		}
	}
	return pids
}
