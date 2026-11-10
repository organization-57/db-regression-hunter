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
	indices := make(map[int]int)
	visits := 0
	var trace func(int, []int)
	trace = func(pid int, path []int) {
		visits++
		if visits > 2048 || len(path) >= 32 {
			return
		}
		for _, p := range path {
			if p == pid {
				return
			}
		}
		s, ok := nodes[pid]
		if !ok || pid == 0 || s.BackendStart == nil || s.State == "unknown" {
			return
		}
		path = append(append([]int{}, path...), pid)
		if len(s.BlockedBy) == 0 {
			if len(path) < 2 {
				return
			}
			index, exists := indices[pid]
			if !exists {
				index = len(roots)
				indices[pid] = index
				roots = append(roots, Blocker{PID: s.PID, Chains: [][]int{}})
			}
			if len(roots[index].Chains) < 64 {
				roots[index].Chains = append(roots[index].Chains, path)
			}
			return
		}
		for _, blocker := range s.BlockedBy {
			trace(blocker, path)
		}
	}
	for _, s := range g.Nodes {
		if s.TargetDatabase && len(s.BlockedBy) > 0 {
			trace(s.PID, nil)
		}
	}
	for n := range roots {
		sort.SliceStable(roots[n].Chains, func(a, b int) bool { return len(roots[n].Chains[a]) > len(roots[n].Chains[b]) })
	}
	return roots
}

func CloneIncident(i Incident) Incident {
	i.BlockingGraph = collector.CloneGraph(i.BlockingGraph)
	i.Blockers = append([]Blocker{}, i.Blockers...)
	for n := range i.Blockers {
		b := &i.Blockers[n]
		b.Chains = append([][]int{}, b.Chains...)
		for j := range b.Chains {
			b.Chains[j] = append([]int{}, b.Chains[j]...)
		}
	}
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
