package collector

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

func TestDisabledStatementsDoNotNeedDatabase(t *testing.T) {
	p := &Postgres{}
	if s := p.collectStatements(context.Background()); s.Available || s.Reason != "disabled" {
		t.Fatal(s)
	}
}

func TestStatementsPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("DEMO_TEST_DATABASE_URL")
	monitorDSN := os.Getenv("DEMO_TEST_MONITOR_DATABASE_URL")
	if dsn == "" || monitorDSN == "" {
		t.Skip("set DEMO_TEST_DATABASE_URL and a distinct DEMO_TEST_MONITOR_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var schema string
	if err := conn.QueryRowContext(ctx, `SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE extname='pg_stat_statements'`).Scan(&schema); err == sql.ErrNoRows {
		t.Skip("install pg_stat_statements and preload it for SQL integration")
	} else if err != nil {
		t.Fatal(err)
	}
	monitor, err := New(monitorDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()
	if _, err := conn.ExecContext(ctx, `CREATE TEMP TABLE hunter_sqlstats_workload(v int); INSERT INTO hunter_sqlstats_workload SELECT generate_series(1,10)`); err != nil {
		t.Fatal(err)
	}
	workload := `SELECT sum(v), pg_sleep($1) FROM pg_temp.hunter_sqlstats_workload`
	execute := func(n int) {
		t.Helper()
		for range n {
			if _, err := conn.ExecContext(ctx, workload, 0.005); err != nil {
				t.Fatal(err)
			}
		}
	}
	execute(1)
	collect := func() sqlstats.Snapshot {
		t.Helper()
		s := monitor.collectStatements(ctx)
		if !s.Available {
			t.Fatalf("SQL stats unavailable: %s", s.Reason)
		}
		return s
	}
	first := collect()
	var id sqlstats.Identity
	// Fixture SQL text is used only by the test to identify its own statement.
	// Production collection calls pg_stat_statements(false) and never reads text.
	query := `SELECT dbid,userid,queryid::text,toplevel FROM ` + quoteSchema(schema) + `.pg_stat_statements WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND query LIKE 'SELECT sum(v), pg_sleep%hunter_sqlstats_workload' AND userid=(SELECT oid FROM pg_roles WHERE rolname=current_user)`
	if err := conn.QueryRowContext(ctx, query).Scan(&id.DatabaseID, &id.UserID, &id.QueryID, &id.TopLevel); err != nil {
		t.Fatal("fixture query not found", err)
	}
	tracker := &sqlstats.Tracker{MaxSampleGap: time.Minute}
	tracker.Observe(first)
	execute(6)
	report := tracker.Observe(collect())
	find := func(r sqlstats.Report) *sqlstats.Query {
		for n := range r.Queries {
			if r.Queries[n].Identity == id {
				return &r.Queries[n]
			}
		}
		return nil
	}
	q := find(report)
	if report.Status != "ready" || q == nil || q.Calls != 6 || q.MeanExecMS < 4 || q.RowsPerCall != 1 {
		t.Fatalf("wrong fixture interval: %+v (%+v)", report, q)
	}
	// A selective reset can be hidden by larger post-reset counters. stats_since
	// must still invalidate this query's delta even when global reset is unchanged.
	if _, err := conn.ExecContext(ctx, `SELECT `+quoteSchema(schema)+`.pg_stat_statements_reset($1::oid,$2::oid,$3::bigint)`, id.UserID, id.DatabaseID, id.QueryID); err != nil {
		t.Fatal(err)
	}
	execute(10)
	report = tracker.Observe(collect())
	if report.ResetStatements < 1 || find(report) != nil {
		t.Fatalf("selective reset escaped detection: %+v", report)
	}
	execute(1)
	report = tracker.Observe(collect())
	if q := find(report); q == nil || q.Calls != 1 {
		t.Fatalf("did not resume after reset: %+v", report)
	}
	snapshot, err := monitor.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.SQL = report
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "hunter_sqlstats_workload") || strings.Contains(string(encoded), "SELECT sum") {
		t.Fatal("SQL text leaked into snapshot JSON")
	}
	// All monitor-role statements must be excluded from source counters.
	var monitorUser uint32
	if err := monitor.db.QueryRowContext(ctx, `SELECT oid FROM pg_roles WHERE rolname=current_user`).Scan(&monitorUser); err != nil {
		t.Fatal(err)
	}
	for _, entry := range snapshot.Statements.Entries {
		if entry.UserID == monitorUser {
			t.Fatal("collector included its own SQL")
		}
	}

	t.Run("baseline_regression_and_recovery", func(t *testing.T) {
		tracker := &sqlstats.Tracker{MaxSampleGap: time.Minute, Regressor: sqlstats.NewRegressor(3, 2, 3, 5, 5)}
		tracker.Observe(collect())
		interval := func(calls int, delay float64) sqlstats.Report {
			t.Helper()
			for range calls {
				if _, err := conn.ExecContext(ctx, workload, delay); err != nil {
					t.Fatal(err)
				}
			}
			return tracker.Observe(collect())
		}
		regression := func(r sqlstats.Report) *sqlstats.Regression {
			for n := range r.Episodes {
				if r.Episodes[n].Identity == id {
					return &r.Episodes[n]
				}
			}
			return nil
		}
		for range 3 {
			if r := interval(5, 0); regression(r) != nil {
				t.Fatal("warmup created a regression", r)
			}
		}
		if r := interval(25, 0); regression(r) != nil {
			t.Fatal("more fast calls created a regression", r)
		}
		if r := interval(5, .03); regression(r) != nil {
			t.Fatal("one slow interval created a regression", r)
		}
		opened := interval(5, .03)
		if e := regression(opened); e == nil || e.Status != "active" || e.Current.MeanExecMS <= e.Current.Comparison.ThresholdMS {
			t.Fatalf("real SQL slowdown not detected: %+v", opened)
		}
		if r := interval(5, 0); regression(r) == nil || regression(r).Status != "recovering" {
			t.Fatal("first normal interval did not start recovery", r)
		}
		closed := interval(5, 0)
		if e := regression(closed); e == nil || e.Status != "resolved" || e.RecoveredAt == nil {
			t.Fatal("SQL did not recover", closed)
		}
	})
	t.Run("insufficient_privileges_preserve_core_collection", func(t *testing.T) {
		var superuser bool
		if err := conn.QueryRowContext(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&superuser); err != nil {
			t.Fatal(err)
		}
		if !superuser {
			t.Skip("SET ROLE check requires a superuser test connection")
		}
		restricted, err := New(dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer restricted.Close()
		restricted.db.SetMaxOpenConns(1)
		if _, err := restricted.db.ExecContext(ctx, `SET ROLE pg_read_all_settings`); err != nil {
			t.Fatal(err)
		}
		s, err := restricted.Collect(ctx)
		if err != nil || s.Statements.Available || s.Statements.Reason != "permission_denied" {
			t.Fatalf("optional source broke core collector: err=%v reason=%s", err, s.Statements.Reason)
		}
	})
}

func quoteSchema(schema string) string { return `"` + strings.ReplaceAll(schema, `"`, `""`) + `"` }

func TestMissingExtensionPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("DEMO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set DEMO_TEST_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := New(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var installed bool
	if err := p.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT FROM pg_extension WHERE extname='pg_stat_statements')`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if installed {
		t.Skip("this test checks a database without pg_stat_statements")
	}
	s, err := p.Collect(ctx)
	if err != nil || s.Statements.Available || s.Statements.Reason != "extension_missing" {
		t.Fatalf("missing extension broke collection: %v, %s", err, s.Statements.Reason)
	}
}
