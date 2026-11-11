package detector

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

// EnrichQueries refreshes only when the selected participants or their queries
// change. Each batch shares an anonymization dictionary; old batches are replaced.
func (d *Detector) EnrichQueries(updates []*Incident, collect func([]collector.QueryTarget) collector.QueryBatch) {
	for _, i := range updates {
		if i.Status == Resolved {
			continue
		}
		queries := queryParticipants(i)
		if len(queries) == 0 || sameParticipants(i.Queries, queries) {
			continue
		}
		targets := make([]collector.QueryTarget, len(queries))
		for n := range queries {
			targets[n] = queries[n].QueryTarget.Clone()
		}
		batch := collect(targets)
		if len(batch.Details) != len(queries) {
			continue
		}
		for n := range queries {
			queries[n].Details = append(json.RawMessage(nil), batch.Details[n]...)
		}
		i.Queries = queries
		i.Tables = append(json.RawMessage(nil), batch.Tables...)
		i.Settings = append(json.RawMessage(nil), batch.Settings...)
		// Save enrichment in the live episode, not just in this API update.
		var current *Incident
		if i.SQLRegression != nil {
			current = d.sqlIncidents[i.SQLRegression.Identity]
		} else {
			for n := range d.signals {
				if c := d.signals[n].current; c != nil && c.ID == i.ID {
					current = c
					break
				}
			}
		}
		if current != nil {
			current.Queries = cloneQueries(i.Queries)
			current.Tables = append(current.Tables[:0:0], i.Tables...)
			current.Settings = append(current.Settings[:0:0], i.Settings...)
		}
	}
}

func queryParticipants(i *Incident) []QueryEvidence {
	var queries []QueryEvidence
	if i.SQLRegression != nil {
		id := i.SQLRegression.Identity
		queries = append(queries, QueryEvidence{Role: "regressed", QueryTarget: collector.QueryTarget{Statement: &id}})
	}
	if i.BlockingGraph == nil {
		return queries
	}
	roots := map[int]bool{}
	blockers := map[int]bool{}
	for _, root := range i.Blockers {
		roots[root.PID] = true
	}
	for _, node := range i.BlockingGraph.Nodes {
		for _, pid := range node.BlockedBy {
			blockers[pid] = true
		}
	}
	nodes := append([]collector.Session(nil), i.BlockingGraph.Nodes...)
	sort.Slice(nodes, func(a, b int) bool { return nodes[a].PID < nodes[b].PID })
	for _, role := range []string{"root_blocker", "blocker", "waiter"} {
		for _, node := range nodes {
			if len(queries) == 4 {
				return queries
			}
			if node.BackendStart == nil || node.State == "unknown" {
				continue
			}
			actual := "waiter"
			if roots[node.PID] {
				actual = "root_blocker"
			} else if blockers[node.PID] {
				actual = "blocker"
			}
			if actual != role {
				continue
			}
			queries = append(queries, QueryEvidence{Role: role, QueryTarget: collector.QueryTarget{PID: node.PID, BackendStart: node.BackendStart, QueryStart: node.QueryStart, TransactionStart: node.TransactionStart, State: node.State}.Clone()})
		}
	}
	return queries
}

func sameParticipants(a, b []QueryEvidence) bool {
	if len(a) != len(b) {
		return false
	}
	for n := range a {
		x, y := a[n], b[n]
		if x.Role != y.Role || x.PID != y.PID || x.State != y.State || !sameTime(x.BackendStart, y.BackendStart) || !sameTime(x.QueryStart, y.QueryStart) || !sameTime(x.TransactionStart, y.TransactionStart) {
			return false
		}
		if (x.Statement == nil) != (y.Statement == nil) || x.Statement != nil && *x.Statement != *y.Statement {
			return false
		}
	}
	return true
}

// SQL has independent episodes per statement, matching main's per-signal model.
// Every source episode is consumed, independently of the public summary.
func (d *Detector) observeSQL(report sqlstats.Report) []*Incident {
	var updates []*Incident
	for _, episode := range report.Episodes {
		i := d.sqlIncidents[episode.Identity]
		opening := i == nil
		if opening {
			// Unknown or already-resolved episodes cannot prove a new regression.
			if episode.Status != "active" && episode.Status != "recovering" {
				continue
			}
			q := episode.Current
			i = &Incident{
				ID:     d.nextIncidentID(),
				Status: Open, StartedAt: episode.StartedAt, DetectedAt: episode.DetectedAt,
				Findings: []Finding{FindingSQLExecutionRegression},
				Trigger:  Trigger{Metric: "sql_mean_exec_ms", Observed: q.MeanExecMS, Baseline: q.Comparison.BaselineMeanExecMS, Threshold: q.Comparison.ThresholdMS, IntervalSeconds: report.IntervalSeconds},
				Peak:     q.MeanExecMS, Recovery: Recovery{RequiredSamples: d.options.RecoverySamples},
			}
			d.sqlIncidents[episode.Identity] = i
		}
		wasUnknown := i.SQLRegression != nil && i.SQLRegression.Status == "unknown"
		i.UpdatedAt = report.At
		q := episode.Current
		i.SQLRegression = &SQLRegression{
			Identity: episode.Identity, Status: episode.Status, Reason: episode.Reason, LastObservedAt: episode.LastObservedAt,
			Calls: q.Calls, MeanExecMS: q.MeanExecMS, CallsPerSecond: q.CallsPerSecond, BaselineCallsPerSecond: q.Comparison.BaselineCallsPerSecond,
			SharedReadsPerCall: q.SharedReadsPerCall, SharedHitsPerCall: q.SharedHitsPerCall,
			TempReadsPerCall: q.TempReadsPerCall, TempWritesPerCall: q.TempWritesPerCall, RowsPerCall: q.RowsPerCall,
		}
		if episode.Current.MeanExecMS > i.Peak {
			i.Peak = episode.Current.MeanExecMS
		}
		switch episode.Status {
		case "recovering", "resolved":
			if i.RecoveryStartedAt == nil {
				at := report.From
				i.RecoveryStartedAt = &at
			}
			i.Status = Recovering
			i.Recovery.NormalSamples = episode.Current.Comparison.RecoverySamples
			if episode.Status == "resolved" {
				i.Status = Resolved
				if episode.RecoveredAt != nil {
					at := *episode.RecoveredAt
					i.ResolvedAt = &at
				}
			}
		default:
			if episode.Status == "unknown" && !wasUnknown {
				i.DataGaps++
			}
			i.Status = Open
			i.RecoveryStartedAt = nil
			i.Recovery.NormalSamples = 0
		}
		update := CloneIncident(*i)
		update.Notify = opening || i.Status == Resolved
		updates = append(updates, &update)
		if i.Status == Resolved {
			delete(d.sqlIncidents, episode.Identity)
		}
	}
	return updates
}

func (d *Detector) missingSQL(at time.Time) []*Incident {
	var updates []*Incident
	for _, i := range d.sqlIncidents {
		i.DataGaps++
		i.UpdatedAt = at
		i.Status = Open
		i.RecoveryStartedAt = nil
		i.Recovery.NormalSamples = 0
		if i.SQLRegression != nil {
			i.SQLRegression.Status = "unknown"
			i.SQLRegression.Reason = "collection_failed"
		}
		copy := CloneIncident(*i)
		copy.Notify = false
		updates = append(updates, &copy)
	}
	sort.Slice(updates, func(a, b int) bool { return updates[a].ID < updates[b].ID })
	return updates
}
