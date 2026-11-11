package detector

import (
	"sort"

	"github.com/makeev/db-regression-hunter/internal/collector"
)

func findBlockers(g *collector.BlockingGraph) []Blocker {
	roots := []Blocker{}
	if g == nil {
		return roots
	}
	nodes := make(map[int]collector.Session)
	for _, s := range g.Nodes {
		nodes[s.PID] = s
	}
	seen := make(map[int]bool)
	var trace func(int)
	trace = func(pid int) {
		if seen[pid] {
			return
		}
		seen[pid] = true
		s, ok := nodes[pid]
		if !ok || pid == 0 || s.BackendStart == nil || s.State == "unknown" {
			return
		}
		if len(s.BlockedBy) == 0 {
			roots = append(roots, Blocker{PID: pid})
			return
		}
		for _, blocker := range s.BlockedBy {
			trace(blocker)
		}
	}
	for _, s := range g.Nodes {
		if s.TargetDatabase && len(s.BlockedBy) > 0 {
			trace(s.PID)
		}
	}
	sort.Slice(roots, func(a, b int) bool { return roots[a].PID < roots[b].PID })
	return roots
}

func CloneIncident(i Incident) Incident {
	i.Findings = append([]Finding(nil), i.Findings...)
	i.Queries = cloneQueries(i.Queries)
	i.Tables = append(i.Tables[:0:0], i.Tables...)
	i.Settings = append(i.Settings[:0:0], i.Settings...)
	if i.SQLRegression != nil {
		r := *i.SQLRegression
		i.SQLRegression = &r
	}
	i.BlockingGraph = collector.CloneGraph(i.BlockingGraph)
	i.Blockers = append([]Blocker{}, i.Blockers...)
	if i.RecoveryStartedAt != nil {
		at := *i.RecoveryStartedAt
		i.RecoveryStartedAt = &at
	}
	if i.ResolvedAt != nil {
		at := *i.ResolvedAt
		i.ResolvedAt = &at
	}

	return i
}

func cloneQueries(queries []QueryEvidence) []QueryEvidence {
	queries = append([]QueryEvidence(nil), queries...)
	for n := range queries {
		queries[n].QueryTarget = queries[n].QueryTarget.Clone()
		queries[n].Details = append(queries[n].Details[:0:0], queries[n].Details...)
	}
	return queries
}
