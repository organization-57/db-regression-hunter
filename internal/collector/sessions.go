package collector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/makeev/db-regression-hunter/internal/sqltext"
)

const (
	planLines = 20
	planChars = 1200
)

type Activity struct {
	PID                   int
	Application           string
	State                 string
	WaitEventType         string
	WaitEvent             string
	TransactionAgeSeconds float64
	QueryAgeSeconds       float64
	Query                 string
}

func (p *Postgres) Activity(ctx context.Context, pids []int) ([]Activity, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ids := make([]int32, 0, len(pids))
	for _, pid := range pids {
		ids = append(ids, int32(pid))
	}
	rows, err := p.db.QueryContext(ctx, `SELECT pid, COALESCE(application_name,''), COALESCE(state,'unknown'),
COALESCE(wait_event_type,''), COALESCE(wait_event,''),
COALESCE(GREATEST(0,extract(epoch FROM clock_timestamp()-xact_start)),0)::float8,
COALESCE(GREATEST(0,extract(epoch FROM clock_timestamp()-query_start)),0)::float8,
COALESCE(query,''), octet_length(query) >= (SELECT setting::int FROM pg_settings WHERE name='track_activity_query_size')-1
FROM pg_stat_activity
WHERE datname=current_database() AND pid<>pg_backend_pid()
AND (pid=ANY($1::int[]) OR (backend_type='client backend' AND usename<>current_user AND state='active' AND query_start IS NOT NULL))
ORDER BY pid=ANY($1::int[]) DESC, query_start LIMIT $2`, ids, len(ids)+5)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Activity
	for rows.Next() {
		var a Activity
		var cut sql.NullBool
		if err := rows.Scan(&a.PID, &a.Application, &a.State, &a.WaitEventType, &a.WaitEvent, &a.TransactionAgeSeconds, &a.QueryAgeSeconds, &a.Query, &cut); err != nil {
			return nil, err
		}
		a.Query = sqltext.Normalize(a.Query)
		if cut.Bool && a.Query != "" && !strings.HasSuffix(a.Query, sqltext.Truncated) {
			a.Query += sqltext.Truncated
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) StatementTexts(ctx context.Context, queryIDs []string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var schema string
	if err := p.db.QueryRowContext(ctx, `SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='pg_stat_statements'`).Scan(&schema); err != nil {
		return nil, err
	}
	rows, err := p.db.QueryContext(ctx, `SELECT DISTINCT ON (queryid) queryid::text, query FROM `+pgx.Identifier{schema}.Sanitize()+`.pg_stat_statements(true)
WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND toplevel AND queryid::text=ANY($1::text[])
ORDER BY queryid, calls DESC`, queryIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	texts := map[string]string{}
	for rows.Next() {
		var id, query string
		if err := rows.Scan(&id, &query); err != nil {
			return nil, err
		}
		texts[id] = sqltext.Normalize(query)
	}
	return texts, rows.Err()
}

func (p *Postgres) Plan(ctx context.Context, query string) (string, error) {
	if !sqltext.Explainable(query) {
		return "", fmt.Errorf("not_explainable")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := p.db.Conn(ctx)
	if err != nil {
		return "", fmt.Errorf("no_connection")
	}
	defer conn.Close()
	var lines []string
	err = conn.Raw(func(driverConn any) error {
		c := driverConn.(*stdlib.Conn).Conn().PgConn()
		defer func() {
			done, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c.Exec(done, "ROLLBACK").ReadAll()
		}()
		if _, err := c.Exec(ctx, "BEGIN READ ONLY; SET LOCAL statement_timeout = '2s'; SET LOCAL lock_timeout = '200ms'").ReadAll(); err != nil {
			return err
		}
		results, err := c.Exec(ctx, "EXPLAIN (GENERIC_PLAN, COSTS) "+strings.TrimSuffix(query, ";")).ReadAll()
		if err != nil {
			return err
		}
		for _, r := range results {
			for _, row := range r.Rows {
				if len(row) > 0 {
					lines = append(lines, string(row[0]))
				}
			}
		}
		return nil
	})
	if err != nil {
		return "", planError(err)
	}
	return compactPlan(lines), nil
}

func planError(err error) error {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return fmt.Errorf("failed")
	}
	switch pg.Code {
	case "42501":
		return fmt.Errorf("permission_denied")
	case "55P03":
		return fmt.Errorf("lock_timeout")
	case "57014":
		return fmt.Errorf("timeout")
	}
	return fmt.Errorf("sqlstate_%s", pg.Code)
}

func compactPlan(lines []string) string {
	var b strings.Builder
	for n, line := range strings.Split(scrubQuoted(strings.Join(lines, "\n")), "\n") {
		if n == planLines || b.Len()+len(line) > planChars {
			b.WriteString("…")
			break
		}
		b.WriteString(strings.TrimRight(line, " "))
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

func scrubQuoted(plan string) string {
	var b strings.Builder
	in := false
	for _, r := range plan {
		switch {
		case r == '\'':
			if !in {
				b.WriteString("'…'")
			}
			in = !in
		case !in:
			b.WriteRune(r)
		}
	}
	return b.String()
}
