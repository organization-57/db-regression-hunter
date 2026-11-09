package demo

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestScenarioSelection(t *testing.T) {
	names, err := parseScenarios(" temp_spill, row_lock ")
	if err != nil || !reflect.DeepEqual(names, []string{"temp_spill", "row_lock"}) {
		t.Fatal(names, err)
	}
	for _, input := range []string{"unknown", "row_lock,", "row_lock,row_lock", " , "} {
		if _, err := parseScenarios(input); err == nil {
			t.Fatalf("accepted invalid selection %q", input)
		}
	}
	names, err = parseScenarios("")
	if err != nil || len(names) != len(scenarios) {
		t.Fatal("default must cover all scenarios", names, err)
	}
}

func TestRepeatForPropagatesParentCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := repeatFor(ctx, time.Second, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("parent timeout was hidden: %v", err)
	}
}

func TestAdditionalScenariosPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("DEMO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set DEMO_TEST_DATABASE_URL for real PostgreSQL tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(24)
	var name string
	if err = db.QueryRowContext(ctx, "SELECT current_database()").Scan(&name); err != nil || name != "demo" {
		t.Fatal("test requires a database named demo", err)
	}
	if err = Seed(ctx, db); err != nil {
		t.Fatal(err)
	}
	await := func(t *testing.T, query string) {
		t.Helper()
		checkCtx, done := context.WithTimeout(ctx, 4*time.Second)
		defer done()
		for checkCtx.Err() == nil {
			var ok bool
			if err := db.QueryRowContext(checkCtx, query).Scan(&ok); err != nil {
				t.Fatal(err)
			}
			if ok {
				return
			}
			pause(checkCtx, 50*time.Millisecond)
		}
		t.Fatal("expected PostgreSQL symptom not observed", query)
	}
	// Cancel each scenario early and verify the blocked application operation recovers.
	for _, kind := range []string{"table_lock", "lock_chain", "session_burst"} {
		t.Run(kind, func(t *testing.T) {
			incidentCtx, stop := context.WithTimeout(ctx, 8*time.Second)
			defer stop()
			done := make(chan error, 1)
			go func() { done <- scenarios[kind].run(incidentCtx, db, 20*time.Second) }()
			var applicationDone chan error
			switch kind {
			case "table_lock":
				await(t, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE relation='demo_shop.orders'::regclass AND mode='AccessExclusiveLock' AND granted)`)
				applicationDone = make(chan error, 1)
				go func() {
					var count int
					applicationDone <- db.QueryRowContext(ctx, "SELECT count(*) FROM demo_shop.orders").Scan(&count)
				}()
				await(t, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock')`)
			case "lock_chain":
				await(t, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock')`)
				applicationDone = make(chan error, 1)
				go func() { applicationDone <- Checkout(ctx, db, 1, 1) }()
				await(t, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity a CROSS JOIN LATERAL unnest(pg_blocking_pids(a.pid)) b(pid) WHERE a.datname=current_database() AND cardinality(pg_blocking_pids(b.pid))>0)`)
			case "session_burst":
				await(t, `SELECT count(*)>=8 FROM pg_stat_activity WHERE datname=current_database() AND state='active' AND wait_event='PgSleep'`)
			}
			stop()
			if err := <-done; err == nil {
				t.Fatal("scenario did not propagate cancellation")
			}
			if applicationDone != nil {
				if err := <-applicationDone; err != nil {
					t.Fatal("application did not recover", err)
				}
			}
			await(t, `SELECT NOT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND (wait_event_type='Lock' OR wait_event='PgSleep'))`)
		})
	}
	t.Run("temp_spill", func(t *testing.T) {
		var before int64
		if err := db.QueryRowContext(ctx, "SELECT temp_bytes FROM pg_stat_database WHERE datname=current_database()").Scan(&before); err != nil {
			t.Fatal(err)
		}
		if err := TempSpillIncident(ctx, db, 500*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		checkCtx, done := context.WithTimeout(ctx, 4*time.Second)
		defer done()
		for checkCtx.Err() == nil {
			var after int64
			if err := db.QueryRowContext(checkCtx, "SELECT temp_bytes FROM pg_stat_database WHERE datname=current_database()").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after > before {
				return
			}
			pause(checkCtx, 100*time.Millisecond)
		}
		t.Fatal("disk sort did not create temporary bytes")
	})
	t.Run("deadlock", func(t *testing.T) {
		// Helper only succeeds if PostgreSQL returns exactly one 40P01 victim.
		if err := reproduceDeadlock(ctx, db); err != nil {
			t.Fatal(err)
		}
		var quantity int
		if err := db.QueryRowContext(ctx, "SELECT quantity FROM demo_shop.inventory WHERE product_id=199 FOR UPDATE NOWAIT").Scan(&quantity); err != nil {
			t.Fatal("deadlock left locks behind", err)
		}
		if err := db.QueryRowContext(ctx, "SELECT quantity FROM demo_shop.inventory WHERE product_id=200 FOR UPDATE NOWAIT").Scan(&quantity); err != nil {
			t.Fatal("deadlock left locks behind", err)
		}
	})
}
