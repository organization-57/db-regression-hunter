package collector

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"
)

const maxSessions = 256

type Session struct {
	PID                   int        `json:"pid"`
	BackendStart          *time.Time `json:"backend_start,omitempty"`
	TargetDatabase        bool       `json:"target_database"`
	Application           string     `json:"application"`
	State                 string     `json:"state"`
	WaitEventType         string     `json:"wait_event_type,omitempty"`
	WaitEvent             string     `json:"wait_event,omitempty"`
	TransactionAgeSeconds float64    `json:"transaction_age_seconds"`
	QueryAgeSeconds       float64    `json:"query_age_seconds"`
	BlockedBy             []int      `json:"blocked_by"`
}

type BlockingGraph struct {
	At       time.Time `json:"at"`
	Complete bool      `json:"complete"`
	Reason   string    `json:"incomplete_reason,omitempty"`
	Nodes    []Session `json:"nodes"`
}

func collectGraph(ctx context.Context, tx *sql.Tx, at time.Time) (*BlockingGraph, error) {
	g := &BlockingGraph{At: at, Complete: true, Nodes: []Session{}}
	var visible bool
	if err := tx.QueryRowContext(ctx, "SELECT pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER')").Scan(&visible); err != nil {
		return nil, err
	}
	if !visible {
		g.Complete = false
		g.Reason = "insufficient_privileges"
	}
	rows, err := tx.QueryContext(ctx, `SELECT pid, backend_start, COALESCE(datname=current_database(),false),
COALESCE(application_name,''), COALESCE(state,'unknown'), COALESCE(wait_event_type,''), COALESCE(wait_event,''),
COALESCE(GREATEST(0,extract(epoch FROM clock_timestamp()-xact_start)),0)::float8,
COALESCE(GREATEST(0,extract(epoch FROM clock_timestamp()-query_start)),0)::float8,
to_json(pg_blocking_pids(pid))
FROM pg_stat_activity WHERE pid<>pg_backend_pid()
ORDER BY (wait_event_type='Lock') DESC NULLS LAST, (datname=current_database()) DESC NULLS LAST, pid
LIMIT 257`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	all := make(map[int]Session)
	for rows.Next() {
		var s Session
		var blocked []byte
		if err := rows.Scan(&s.PID, &s.BackendStart, &s.TargetDatabase, &s.Application, &s.State, &s.WaitEventType, &s.WaitEvent, &s.TransactionAgeSeconds, &s.QueryAgeSeconds, &blocked); err != nil {
			return nil, err
		}
		if len(all) == maxSessions {
			g.Complete = false
			g.Reason = "session_limit"
			continue
		}
		if err := json.Unmarshal(blocked, &s.BlockedBy); err != nil {
			return nil, err
		}
		all[s.PID] = s
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Keep only target waiters and their ancestors, including blockers from other databases.
	seen := make(map[int]bool)
	links := 0
	var visit func(int)
	visit = func(pid int) {
		if seen[pid] {
			return
		}
		seen[pid] = true
		s, ok := all[pid]
		if !ok {
			g.Complete = false
			g.Reason = "missing_blocker"
			return
		}
		blocked := []int{}
		unique := make(map[int]bool)
		for _, blocker := range s.BlockedBy {
			if unique[blocker] {
				continue
			}
			unique[blocker] = true
			if links == 2048 {
				g.Complete = false
				g.Reason = "link_limit"
				break
			}
			blocked = append(blocked, blocker)
			links++
		}
		if len(s.BlockedBy) > 0 && len(blocked) == 0 {
			return
		}
		s.BlockedBy = blocked
		g.Nodes = append(g.Nodes, s)
		for _, blocker := range blocked {
			visit(blocker)
		}
	}
	for pid, s := range all {
		if s.TargetDatabase && len(s.BlockedBy) > 0 {
			visit(pid)
		}
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].PID < g.Nodes[j].PID })
	return g, nil
}

func CloneSnapshot(s Snapshot) Snapshot {
	s.BlockingGraph = CloneGraph(s.BlockingGraph)
	return s
}

func CloneGraph(g *BlockingGraph) *BlockingGraph {
	if g == nil {
		return nil
	}
	copyGraph := *g
	copyGraph.Nodes = append([]Session{}, g.Nodes...)
	for i := range copyGraph.Nodes {
		n := &copyGraph.Nodes[i]
		n.BlockedBy = append([]int{}, n.BlockedBy...)
		if n.BackendStart != nil {
			at := *n.BackendStart
			n.BackendStart = &at
		}
	}
	return &copyGraph
}
