// Package demo supplies synthetic shop data and bounded workloads for the local demo database.
package demo

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strconv"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed schema.sql
var schema string

type Config struct {
	DSN                        string
	Warmup, Duration, Cooldown time.Duration
	Scenarios                  []string
}

func LoadConfig() (Config, error) {
	c := Config{DSN: os.Getenv("DEMO_DATABASE_URL")}
	if c.DSN == "" {
		return c, fmt.Errorf("DEMO_DATABASE_URL is required")
	}
	poll := 10 * time.Second
	var err error
	if v := os.Getenv("POLL_INTERVAL"); v != "" {
		poll, err = time.ParseDuration(v)
		if err != nil || poll < time.Second {
			return c, fmt.Errorf("invalid POLL_INTERVAL")
		}
	}
	baseline, confirm := 20, 3
	for _, item := range []struct {
		key    string
		target *int
	}{{"BASELINE_SAMPLES", &baseline}, {"CONFIRM_SAMPLES", &confirm}} {
		if v := os.Getenv(item.key); v != "" {
			*item.target, err = strconv.Atoi(v)
			if err != nil || *item.target < 1 || *item.target > 10000 {
				return c, fmt.Errorf("invalid %s", item.key)
			}
		}
	}
	c.Warmup = time.Duration(baseline+confirm+2) * poll
	c.Duration = time.Duration(confirm+2)*poll + 10*time.Second
	c.Cooldown = time.Minute
	for _, item := range []struct {
		key    string
		target *time.Duration
	}{{"DEMO_WARMUP", &c.Warmup}, {"DEMO_INCIDENT_DURATION", &c.Duration}, {"DEMO_COOLDOWN", &c.Cooldown}} {
		if v := os.Getenv(item.key); v != "" {
			*item.target, err = time.ParseDuration(v)
			if err != nil || *item.target < time.Second {
				return c, fmt.Errorf("%s must be a duration >= 1s", item.key)
			}
		}
	}
	c.Scenarios, err = parseScenarios(os.Getenv("DEMO_SCENARIOS"))
	return c, err
}

func Seed(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, schema); err != nil {
		return err
	}
	var seeded bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM demo_shop.seed_versions WHERE version=1)").Scan(&seeded); err != nil {
		return err
	}
	if !seeded {
		_, err = tx.ExecContext(ctx, `
INSERT INTO demo_shop.customers (email,name,created_at)
SELECT 'customer-'||i||'@example.test', 'Customer '||i, now()-(i%180)*interval '1 day' FROM generate_series(1,2000) i;
INSERT INTO demo_shop.products (name,price_cents)
SELECT 'Product '||i, 500+(i*137)%20000 FROM generate_series(1,200) i;
INSERT INTO demo_shop.inventory (product_id,quantity) SELECT id,10000 FROM demo_shop.products;
INSERT INTO demo_shop.orders (customer_id,status,total_cents,created_at)
SELECT 1+(i%2000), 'paid',
       (SELECT sum(price_cents) FROM demo_shop.products WHERE id IN (1+(i%200),1+((i+1)%200),1+((i+2)%200))),
       now()-(i%30)*interval '1 day'-(i%86400)*interval '1 second'
FROM generate_series(1,10000) i;
INSERT INTO demo_shop.order_items (order_id,product_id,quantity,price_cents)
SELECT o.id,p.id,1,p.price_cents FROM demo_shop.orders o JOIN demo_shop.products p
ON p.id IN (1+(o.id%200),1+((o.id+1)%200),1+((o.id+2)%200));
INSERT INTO demo_shop.payments (order_id,amount_cents,status,created_at)
SELECT id,total_cents,'captured',created_at FROM demo_shop.orders;
INSERT INTO demo_shop.seed_versions VALUES (1);`)
		if err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "ANALYZE demo_shop.customers; ANALYZE demo_shop.products; ANALYZE demo_shop.inventory; ANALYZE demo_shop.orders; ANALYZE demo_shop.order_items; ANALYZE demo_shop.payments")
	return err
}

// Checkout updates stock, an order and its payment atomically.
func Checkout(ctx context.Context, db *sql.DB, customer, product int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE demo_shop.inventory SET quantity=CASE WHEN quantity>0 THEN quantity-1 ELSE 10000 END, updated_at=now() WHERE product_id=$1`, product); err != nil {
		return err
	}
	var orderID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO demo_shop.orders(customer_id,status,total_cents)
SELECT $1,'paid',price_cents FROM demo_shop.products WHERE id=$2 RETURNING id`, customer, product).Scan(&orderID)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO demo_shop.order_items SELECT $1,id,1,price_cents FROM demo_shop.products WHERE id=$2`, orderID, product); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO demo_shop.payments(order_id,amount_cents,status) SELECT id,total_cents,'captured' FROM demo_shop.orders WHERE id=$1`, orderID); err != nil {
		return err
	}
	return tx.Commit()
}

// LockIncident holds a real row lock while checkout workers wait for that row.
func LockIncident(ctx context.Context, db *sql.DB, duration time.Duration, started chan<- struct{}) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE demo_shop.inventory SET updated_at=now() WHERE product_id=1"); err != nil {
		return err
	}
	if started != nil {
		close(started)
	}
	if !pause(ctx, duration) {
		return ctx.Err()
	}
	return tx.Commit()
}

func ReportIncident(ctx context.Context, db *sql.DB, duration time.Duration) error {
	// Deliberate server-side delay models a slow report without CPU or disk stress.
	_, err := db.ExecContext(ctx, `SELECT pg_sleep($1), COALESCE(sum(total_cents),0) FROM demo_shop.orders WHERE created_at >= now()-interval '30 days'`, duration.Seconds())
	return err
}

func Run(ctx context.Context, cfg Config) error {
	if err := os.Remove("/tmp/demo-ready"); err != nil && !os.IsNotExist(err) {
		return err
	}
	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return fmt.Errorf("invalid demo connection configuration")
	}
	defer db.Close()
	db.SetMaxOpenConns(24)
	db.SetMaxIdleConns(8)
	setupCtx, cancelSetup := context.WithTimeout(ctx, time.Minute)
	var name string
	err = db.QueryRowContext(setupCtx, "SELECT current_database()").Scan(&name)
	if err != nil || name != "demo" {
		cancelSetup()
		return fmt.Errorf("demo workload requires a reachable database named demo")
	}
	// Keep the advisory lock on a dedicated connection for the whole process lifetime.
	owner, err := db.Conn(setupCtx)
	if err != nil {
		cancelSetup()
		return fmt.Errorf("cannot acquire demo connection")
	}
	defer owner.Close()
	var acquired bool
	err = owner.QueryRowContext(setupCtx, "SELECT pg_try_advisory_lock(72638104)").Scan(&acquired)
	if err != nil || !acquired {
		cancelSetup()
		return fmt.Errorf("another demo workload is already running")
	}
	defer func() {
		unlockCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		owner.ExecContext(unlockCtx, "SELECT pg_advisory_unlock(72638104)")
	}()
	err = Seed(setupCtx, db)
	cancelSetup()
	if err != nil {
		return fmt.Errorf("demo seed failed")
	}
	if err = os.WriteFile("/tmp/demo-ready", []byte("ready\n"), 0600); err != nil {
		return err
	}
	slog.Info("demo shop ready", "customers", 2000, "products", 200, "initial_orders", 10000, "warmup", cfg.Warmup, "incident_duration", cfg.Duration, "cooldown", cfg.Cooldown, "scenarios", cfg.Scenarios)
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	worker := func(name string, interval, timeout time.Duration, operation func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					jobCtx, done := context.WithTimeout(ctx, timeout)
					err := operation(jobCtx)
					done()
					if err != nil && ctx.Err() == nil {
						slog.Warn("demo operation failed", "operation", name)
					}
				}
			}
		}()
	}
	for range 3 {
		worker("browse", 300*time.Millisecond, 3*time.Second, func(ctx context.Context) error {
			rows, err := db.QueryContext(ctx, `SELECT o.id,o.status,o.total_cents,p.name,i.quantity FROM demo_shop.orders o
JOIN demo_shop.order_items i ON i.order_id=o.id JOIN demo_shop.products p ON p.id=i.product_id
WHERE o.customer_id=$1 ORDER BY o.created_at DESC LIMIT 20`, 1+rand.IntN(2000))
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
			}
			return rows.Err()
		})
	}
	worker("checkout", time.Second, 5*time.Second, func(ctx context.Context) error { return Checkout(ctx, db, 1+rand.IntN(2000), 2+rand.IntN(199)) })
	for range 2 {
		worker("popular-product checkout", time.Second, cfg.Duration+30*time.Second, func(ctx context.Context) error { return Checkout(ctx, db, 1+rand.IntN(2000), 1) })
	}
	worker("retention", time.Minute, 5*time.Second, func(ctx context.Context) error {
		_, err := db.ExecContext(ctx, `DELETE FROM demo_shop.orders WHERE id < (SELECT max(id)-20000 FROM demo_shop.orders)`)
		return err
	})
	if !pause(ctx, cfg.Warmup) {
		return nil
	}
	order := append([]string(nil), cfg.Scenarios...)
	var previous string
	for cycle := 1; ctx.Err() == nil; cycle++ {
		index := (cycle - 1) % len(order)
		if index == 0 {
			rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
			if len(order) > 1 && order[0] == previous {
				j := 1 + rand.IntN(len(order)-1)
				order[0], order[j] = order[j], order[0]
			}
			slog.Info("demo scenario round shuffled", "round", (cycle-1)/len(order)+1, "scenarios", order)
		}
		kind := order[index]
		previous = kind
		s := scenarios[kind]
		slog.Info("demo incident started", "scenario", kind, "duration", cfg.Duration, "cycle", cycle, "expected_symptom", s.symptom)
		incidentCtx, done := context.WithTimeout(ctx, cfg.Duration+10*time.Second)
		err = s.run(incidentCtx, db, cfg.Duration)
		done()
		if err != nil && ctx.Err() == nil {
			slog.Warn("demo incident failed", "scenario", kind)
		} else {
			slog.Info("demo incident finished", "scenario", kind)
		}
		if !pause(ctx, cfg.Cooldown) {
			return nil
		}
	}
	return nil
}

func pause(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
