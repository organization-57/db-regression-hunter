package demo

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/detector"
)

// Run against a dedicated PostgreSQL demo database without the workload service.
func TestPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("DEMO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set DEMO_TEST_DATABASE_URL for real PostgreSQL tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name string
	if err = db.QueryRowContext(ctx, "SELECT current_database()").Scan(&name); err != nil || name != "demo" {
		t.Fatal("test requires a database named demo", err)
	}
	if err = Seed(ctx, db); err != nil {
		t.Fatal(err)
	}
	var before, after int
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM demo_shop.orders").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = Seed(ctx, db); err != nil {
		t.Fatal("repeat seed", err)
	}
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM demo_shop.orders").Scan(&after); err != nil || after != before {
		t.Fatal("seed duplicated orders", before, after, err)
	}
	if err = Checkout(ctx, db, 1, 2); err != nil {
		t.Fatal(err)
	}
	var consistent bool
	err = db.QueryRowContext(ctx, `SELECT o.total_cents=p.amount_cents AND o.total_cents=sum(i.quantity*i.price_cents)
FROM demo_shop.orders o JOIN demo_shop.payments p ON p.order_id=o.id JOIN demo_shop.order_items i ON i.order_id=o.id
WHERE o.id=(SELECT max(id) FROM demo_shop.orders) GROUP BY o.total_cents,p.amount_cents`).Scan(&consistent)
	if err != nil || !consistent {
		t.Fatal("checkout totals disagree", err)
	}
	pg, err := collector.New(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	warm := func() *detector.Detector {
		d := detector.New(20, 2, 3)
		for range 20 {
			s, err := pg.Collect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			d.Observe(s)
		}
		return d
	}
	awaitIncident := func(d *detector.Detector) *detector.Incident {
		t.Helper()
		for ctx.Err() == nil {
			s, err := pg.Collect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if i := d.Observe(s); i != nil {
				return i
			}
			if !pause(ctx, 100*time.Millisecond) {
				break
			}
		}
		t.Fatal("incident not detected before timeout")
		return nil
	}
	d := warm()
	started := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() { lockDone <- LockIncident(ctx, db, 2500*time.Millisecond, started) }()
	select {
	case <-started:
	case err := <-lockDone:
		t.Fatal("failed to acquire lock", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	checkoutDone := make(chan error, 1)
	go func() { checkoutDone <- Checkout(ctx, db, 1, 1) }()
	i := awaitIncident(d)
	if !strings.Contains(i.Hypothesis, "Блокировки") {
		t.Fatalf("expected lock evidence: %+v", i)
	}
	if err = <-lockDone; err != nil {
		t.Fatal(err)
	}
	if err = <-checkoutDone; err != nil {
		t.Fatal("checkout did not recover", err)
	}
	s, err := pg.Collect(ctx)
	if err != nil || s.LockWaiters != 0 {
		t.Fatal("lock waiters remain", s, err)
	}
	d = warm()
	reportDone := make(chan error, 1)
	go func() { reportDone <- ReportIncident(ctx, db, 2500*time.Millisecond) }()
	i = awaitIncident(d)
	if strings.Contains(i.Hypothesis, "Блокировки") {
		t.Fatal("slow report incorrectly attributed to locks")
	}
	if err = <-reportDone; err != nil {
		t.Fatal(err)
	}
	s, err = pg.Collect(ctx)
	if err != nil || s.Active != 0 {
		t.Fatal("report did not finish", s, err)
	}
}
