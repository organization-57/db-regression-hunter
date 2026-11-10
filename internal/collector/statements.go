package collector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

// Fetch the entire bounded set before ranking deltas. A cumulative SQL LIMIT
// would hide newly expensive statements and make reappearing entries ambiguous.
const maxStatementEntries = 10000

func (p *Postgres) collectStatements(parent context.Context) sqlstats.Snapshot {
	sample := sqlstats.Snapshot{At: time.Now(), Reason: "disabled"}
	if !p.SQLStatsEnabled {
		return sample
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	conn, err := p.db.Conn(ctx)
	if err != nil {
		sample.Reason = statementError(err)
		return sample
	}
	defer conn.Close()
	var schema, tracking, queryIDs string
	var permitted bool
	err = conn.QueryRowContext(ctx, `SELECT n.nspname,
 pg_has_role(current_user, 'pg_read_all_stats', 'USAGE'),
 COALESCE(current_setting('pg_stat_statements.track', true), ''),
 current_setting('compute_query_id')
 FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
 WHERE e.extname='pg_stat_statements'`).Scan(&schema, &permitted, &tracking, &queryIDs)
	if err != nil {
		sample.Reason = statementError(err)
		return sample
	}
	if !permitted {
		sample.Reason = "permission_denied"
		return sample
	}
	if tracking == "none" {
		sample.Reason = "tracking_disabled"
		return sample
	}
	if queryIDs == "off" {
		sample.Reason = "query_id_disabled"
		return sample
	}
	prefix := pgx.Identifier{schema}.Sanitize() + "."
	readInfo := func() (sqlstats.Snapshot, error) {
		var info sqlstats.Snapshot
		err := conn.QueryRowContext(ctx, `SELECT clock_timestamp(), pg_postmaster_start_time(), stats_reset, dealloc FROM `+prefix+`pg_stat_statements_info`).Scan(&info.At, &info.ServerStartedAt, &info.ResetAt, &info.Deallocations)
		return info, err
	}
	before, err := readInfo()
	if err != nil {
		sample.Reason = statementError(err)
		return sample
	}
	// showtext=false avoids reading query texts. Excluding the dedicated monitor
	// role removes Hunter's own polling SQL without filtering by sensitive text.
	rows, err := conn.QueryContext(ctx, fmt.Sprintf(`SELECT dbid, userid, queryid::text, toplevel, stats_since,
 calls, total_exec_time, shared_blks_read, shared_blks_hit,
 temp_blks_read, temp_blks_written, rows
 FROM %spg_stat_statements(false)
 WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND userid<>(SELECT oid FROM pg_roles WHERE rolname=current_user)
 AND toplevel AND queryid IS NOT NULL
 ORDER BY dbid, userid, queryid LIMIT %d`, prefix, maxStatementEntries+1))
	if err != nil {
		sample.Reason = statementError(err)
		return sample
	}
	var entries []sqlstats.Counters
	for rows.Next() {
		var entry sqlstats.Counters
		if err = rows.Scan(&entry.DatabaseID, &entry.UserID, &entry.QueryID, &entry.TopLevel, &entry.Since,
			&entry.Calls, &entry.TotalExecMS, &entry.SharedReads, &entry.SharedHits, &entry.TempReads, &entry.TempWrites, &entry.Rows); err != nil {
			break
		}
		entries = append(entries, entry)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		sample.Reason = statementError(err)
		return sample
	}
	if len(entries) > maxStatementEntries {
		sample.Reason = "capacity_exceeded"
		return sample
	}
	after, err := readInfo()
	if err != nil {
		sample.Reason = statementError(err)
		return sample
	}
	if !before.ResetAt.Equal(after.ResetAt) || before.Deallocations != after.Deallocations || !before.ServerStartedAt.Equal(after.ServerStartedAt) {
		sample.Reason = "changed_during_collection"
		return sample
	}
	after.Available = true
	after.Entries = entries
	return after
}

func statementError(err error) string {
	// Return stable capability/error codes, never server text, connection strings
	// or SQL. No rows from discovery means the extension is not installed.
	if errors.Is(err, sql.ErrNoRows) {
		return "extension_missing"
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "42P01", "3F000":
			return "extension_missing"
		case "55000":
			return "preload_required"
		case "42501":
			return "permission_denied"
		case "42703", "42883":
			return "unsupported_version"
		}
	}
	return "collection_failed"
}
