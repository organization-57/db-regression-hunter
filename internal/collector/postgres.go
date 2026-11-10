package collector

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

type Snapshot struct {
	At                 time.Time         `json:"at"`
	Active             int               `json:"active_sessions"`
	LockWaiters        int               `json:"lock_waiters"`
	OldestQuerySeconds float64           `json:"oldest_query_seconds"`
	Commits            int64             `json:"commits"`
	Rollbacks          int64             `json:"rollbacks"`
	BlocksRead         int64             `json:"blocks_read"`
	BlocksHit          int64             `json:"blocks_hit"`
	TempBytes          int64             `json:"temp_bytes"`
	Blocking           BlockingGraph     `json:"blocking"`
	SQL                sqlstats.Report   `json:"sql"`
	Statements         sqlstats.Snapshot `json:"-"`
}

// Session contains diagnostic metadata only: no SQL text or application data.
// BackendStartedAt distinguishes reused PIDs across observations.
type Session struct {
	PID                  int        `json:"pid"`
	BackendStartedAt     *time.Time `json:"backend_started_at"`
	State                string     `json:"state"`
	WaitEventType        string     `json:"wait_event_type"`
	WaitEvent            string     `json:"wait_event"`
	TransactionStartedAt *time.Time `json:"transaction_started_at"`
	QueryStartedAt       *time.Time `json:"query_started_at"`
}

// An edge points from a waiting backend to a blocking backend. PID 0 denotes
// a prepared transaction; a missing participant is not assumed to be a root.
type BlockingEdge struct {
	WaiterPID  int `json:"waiter_pid"`
	BlockerPID int `json:"blocker_pid"`
}

type BlockingGraph struct {
	Sessions []Session      `json:"sessions"`
	Edges    []BlockingEdge `json:"edges"`
}

type Postgres struct {
	db              *sql.DB
	SQLStatsEnabled bool
}

func New(dsn string) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)
	return &Postgres{db: db, SQLStatsEnabled: true}, nil
}

func (p *Postgres) Close() error { return p.db.Close() }

func (p *Postgres) Collect(ctx context.Context) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s := Snapshot{}
	var graphJSON []byte
	// Exclude our own backend. No SQL texts or application data are collected.
	err := p.db.QueryRowContext(ctx, `
WITH activity AS MATERIALIZED (
    SELECT pid, datname, state, backend_start, xact_start, query_start,
           wait_event_type, wait_event
    FROM pg_stat_activity WHERE pid<>pg_backend_pid()
), local_activity AS MATERIALIZED (
    SELECT * FROM activity WHERE datname=current_database()
), edges AS MATERIALIZED (
    SELECT DISTINCT a.pid AS waiter_pid, b.pid AS blocker_pid
    FROM local_activity a
    CROSS JOIN LATERAL unnest(pg_blocking_pids(a.pid)) b(pid)
    WHERE a.wait_event_type='Lock'
), participants AS (
    SELECT pid FROM local_activity WHERE wait_event_type='Lock'
    UNION SELECT blocker_pid FROM edges
)
SELECT clock_timestamp(),
       (SELECT count(*) FROM local_activity WHERE state='active'),
       (SELECT count(*) FROM local_activity WHERE wait_event_type='Lock'),
       COALESCE((SELECT max(GREATEST(0, extract(epoch FROM clock_timestamp()-query_start))) FROM local_activity WHERE state='active'), 0)::float8,
       xact_commit, xact_rollback, blks_read, blks_hit, temp_bytes,
       json_build_object(
           'sessions', COALESCE((SELECT json_agg(json_build_object(
               'pid', a.pid, 'backend_started_at', a.backend_start,
               'state', COALESCE(a.state,''),
               'wait_event_type', COALESCE(a.wait_event_type,''),
               'wait_event', COALESCE(a.wait_event,''),
               'transaction_started_at', a.xact_start,
               'query_started_at', a.query_start) ORDER BY a.pid)
               FROM activity a JOIN participants p USING (pid)), '[]'::json),
           'edges', COALESCE((SELECT json_agg(e ORDER BY waiter_pid,blocker_pid) FROM edges e), '[]'::json))
FROM pg_stat_database WHERE datname=current_database()`).Scan(&s.At, &s.Active, &s.LockWaiters, &s.OldestQuerySeconds, &s.Commits, &s.Rollbacks, &s.BlocksRead, &s.BlocksHit, &s.TempBytes, &graphJSON)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(graphJSON, &s.Blocking)
	if err != nil {
		return s, err
	}
	// Optional SQL diagnostics have a separate deadline and cannot turn a
	// successful core collection into an outage of the blocking detector.
	s.Statements = p.collectStatements(ctx)
	return s, nil
}

// Clone gives the store and detector independent ownership of session metadata.
func (g BlockingGraph) Clone() BlockingGraph {
	g.Edges = append([]BlockingEdge(nil), g.Edges...)
	g.Sessions = append([]Session(nil), g.Sessions...)
	for n := range g.Sessions {
		s := &g.Sessions[n]
		if s.BackendStartedAt != nil {
			at := *s.BackendStartedAt
			s.BackendStartedAt = &at
		}
		if s.TransactionStartedAt != nil {
			at := *s.TransactionStartedAt
			s.TransactionStartedAt = &at
		}
		if s.QueryStartedAt != nil {
			at := *s.QueryStartedAt
			s.QueryStartedAt = &at
		}
	}
	return g
}

func (s Snapshot) Clone() Snapshot {
	s.Blocking = s.Blocking.Clone()
	s.SQL = s.SQL.Clone()
	s.Statements.Entries = append([]sqlstats.Counters(nil), s.Statements.Entries...)
	return s
}
