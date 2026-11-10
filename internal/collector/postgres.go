package collector

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Snapshot struct {
	At                 time.Time      `json:"at"`
	Active             int            `json:"active_sessions"`
	LockWaiters        int            `json:"lock_waiters"`
	OldestQuerySeconds float64        `json:"oldest_query_seconds"`
	Commits            int64          `json:"commits"`
	Rollbacks          int64          `json:"rollbacks"`
	BlocksRead         int64          `json:"blocks_read"`
	BlocksHit          int64          `json:"blocks_hit"`
	TempBytes          int64          `json:"temp_bytes"`
	Deadlocks          int64          `json:"deadlocks"`
	StatsReset         *time.Time     `json:"-"`
	PostmasterStart    time.Time      `json:"-"`
	BlockingGraph      *BlockingGraph `json:"blocking_graph,omitempty"`
}

type Postgres struct{ db *sql.DB }

func New(dsn string) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)
	return &Postgres{db: db}, nil
}

func (p *Postgres) Close() error { return p.db.Close() }

func (p *Postgres) Collect(ctx context.Context) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s := Snapshot{}
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return s, err
	}
	defer tx.Rollback()
	// Exclude our own backend. No SQL texts or application data are collected.
	err = tx.QueryRowContext(ctx, `
SELECT clock_timestamp(),
       (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state='active'),
       (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock'),
       COALESCE((SELECT max(GREATEST(0, extract(epoch FROM clock_timestamp()-query_start))) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state='active'), 0)::float8,
       xact_commit, xact_rollback, blks_read, blks_hit, temp_bytes, deadlocks, stats_reset, pg_postmaster_start_time()
FROM pg_stat_database WHERE datname=current_database()`).Scan(&s.At, &s.Active, &s.LockWaiters, &s.OldestQuerySeconds, &s.Commits, &s.Rollbacks, &s.BlocksRead, &s.BlocksHit, &s.TempBytes, &s.Deadlocks, &s.StatsReset, &s.PostmasterStart)
	if err != nil {
		return s, err
	}
	s.BlockingGraph, err = collectGraph(ctx, tx, s.At)
	if err != nil {
		return s, err
	}
	return s, tx.Commit()
}
