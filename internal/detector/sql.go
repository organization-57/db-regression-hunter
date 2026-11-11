package detector

import (
	"fmt"
	"sort"
	"time"

	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

func (d *Detector) addSQLContext(i *Incident, report sqlstats.Report) {
	if report.Status == "" {
		return
	}
	if i.SQLContext == nil {
		i.SQLContext = &sqlstats.Context{}
		for _, previous := range d.sqlHistory {
			if !previous.At.After(i.StartedAt) {
				i.SQLContext.Before = sqlstats.AppendRecent(i.SQLContext.Before, previous)
			} else {
				i.SQLContext.Observe(previous)
			}
		}
	}
	i.SQLContext.Observe(report)
}

// SQL has independent episodes per statement, matching main's per-signal model.
// Complete internal episodes are consumed before the API's top-20 limit.
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
				ID:     fmt.Sprintf("%d-sql-%d-%d-%s-%t", episode.DetectedAt.UnixNano(), q.DatabaseID, q.UserID, q.QueryID, q.TopLevel),
				Status: Open, StartedAt: episode.StartedAt, DetectedAt: episode.DetectedAt,
				Finding: FindingSQLExecutionRegression,
				Trigger: Trigger{Metric: "sql_mean_exec_ms", Observed: q.MeanExecMS, Baseline: q.Comparison.BaselineMeanExecMS, Threshold: q.Comparison.ThresholdMS, IntervalSeconds: report.IntervalSeconds},
				Peak:    q.MeanExecMS, Recovery: Recovery{RequiredSamples: d.options.RecoverySamples},
			}
			d.sqlIncidents[episode.Identity] = i
		}
		wasUnknown := i.SQLRegression != nil && i.SQLRegression.Status == "unknown"
		i.UpdatedAt = report.At
		e := episode.Clone()
		i.SQLRegression = &e
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
		d.addSQLContext(i, report)
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
