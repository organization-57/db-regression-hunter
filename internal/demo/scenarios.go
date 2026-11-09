package demo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const defaultScenarios = "row_lock,slow_report,table_lock,lock_chain,temp_spill,session_burst,deadlock"

type scenario struct {
	symptom string
	run     func(context.Context, *sql.DB, time.Duration) error
}

var scenarios = map[string]scenario{
	"row_lock":      {"popular-product checkouts wait for a row lock", func(ctx context.Context, db *sql.DB, d time.Duration) error { return LockIncident(ctx, db, d, nil) }},
	"slow_report":   {"oldest query age grows without Lock waits", ReportIncident},
	"table_lock":    {"reads and writes wait for an exclusive table lock", TableLockIncident},
	"lock_chain":    {"checkouts wait for a transaction that is itself blocked", LockChainIncident},
	"temp_spill":    {"temporary bytes grow due to disk sorts; no age alert expected", TempSpillIncident},
	"session_burst": {"eight additional active sessions with long queries", SessionBurstIncident},
	"deadlock":      {"PostgreSQL resolves deadlocks; rollback counter grows", DeadlockIncident},
}

func parseScenarios(value string) ([]string, error) {
	if value == "" {
		value = defaultScenarios
	}
	names := strings.Split(value, ",")
	seen := make(map[string]bool)
	for i, name := range names {
		name = strings.TrimSpace(name)
		if _, ok := scenarios[name]; !ok {
			return nil, fmt.Errorf("unknown DEMO_SCENARIOS entry %q; available: %s", name, defaultScenarios)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate DEMO_SCENARIOS entry %q", name)
		}
		names[i], seen[name] = name, true
	}
	return names, nil
}

func TableLockIncident(ctx context.Context, db *sql.DB, duration time.Duration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Model the lock footprint of blocking DDL without changing the schema.
	if _, err = tx.ExecContext(ctx, "LOCK TABLE demo_shop.orders IN ACCESS EXCLUSIVE MODE"); err != nil {
		return err
	}
	if !pause(ctx, duration) {
		return ctx.Err()
	}
	return tx.Rollback()
}

func LockChainIncident(ctx context.Context, db *sql.DB, duration time.Duration) error {
	leader, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer leader.Rollback()
	if _, err = leader.ExecContext(ctx, "UPDATE demo_shop.inventory SET updated_at=now() WHERE product_id=2"); err != nil {
		return err
	}
	middle, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer middle.Rollback()
	if _, err = middle.ExecContext(ctx, "UPDATE demo_shop.inventory SET updated_at=now() WHERE product_id=1"); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		_, err := middle.ExecContext(ctx, "UPDATE demo_shop.inventory SET updated_at=now() WHERE product_id=2")
		done <- err
	}()
	// Checkouts queue behind middle, which is queued behind leader.
	waited := pause(ctx, duration)
	if err = leader.Rollback(); err != nil && ctx.Err() == nil {
		<-done
		return err
	}
	err = <-done
	if !waited {
		return ctx.Err()
	}
	return err
}

func TempSpillIncident(ctx context.Context, db *sql.DB, duration time.Duration) error {
	return repeatFor(ctx, duration, func(ctx context.Context) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		// Settings are transaction-local; space and parallelism are bounded.
		if _, err = tx.ExecContext(ctx, `SET LOCAL work_mem='64kB'; SET LOCAL temp_file_limit='32MB'; SET LOCAL max_parallel_workers_per_gather=0; SET LOCAL statement_timeout='3s'`); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `SELECT count(*) FROM (SELECT md5(i::text) AS payload FROM generate_series(1,30000) i ORDER BY payload) sorted`); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func SessionBurstIncident(ctx context.Context, db *sql.DB, duration time.Duration) error {
	const sessions = 8
	results := make(chan error, sessions)
	for range sessions {
		go func() { _, err := db.ExecContext(ctx, "SELECT pg_sleep($1)", duration.Seconds()); results <- err }()
	}
	var errs []error
	for range sessions {
		if err := <-results; err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func DeadlockIncident(ctx context.Context, db *sql.DB, duration time.Duration) error {
	count := 0
	err := repeatFor(ctx, duration, func(ctx context.Context) error {
		if err := reproduceDeadlock(ctx, db); err != nil {
			return err
		}
		count++
		return nil
	})
	slog.Info("demo deadlocks reproduced", "count", count, "expected_sqlstate", "40P01")
	return err
}

func reproduceDeadlock(ctx context.Context, db *sql.DB) error {
	first, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer first.Rollback()
	second, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer second.Rollback()
	for i, tx := range []*sql.Tx{first, second} {
		if _, err = tx.ExecContext(ctx, "SET LOCAL deadlock_timeout='100ms'"); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE demo_shop.inventory SET updated_at=now() WHERE product_id=$1", 199+i); err != nil {
			return err
		}
	}
	results := make(chan error, 2)
	for i, tx := range []*sql.Tx{first, second} {
		go func(tx *sql.Tx, product int) {
			_, err := tx.ExecContext(ctx, "UPDATE demo_shop.inventory SET updated_at=now() WHERE product_id=$1", product)
			tx.Rollback() // Always release both rows, including the surviving transaction.
			results <- err
		}(tx, 200-i)
	}
	victims := 0
	var unexpected []error
	for range 2 {
		err = <-results
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
			victims++
		} else if err != nil {
			unexpected = append(unexpected, err)
		}
	}
	if len(unexpected) > 0 {
		return errors.Join(unexpected...)
	}
	if victims != 1 {
		return fmt.Errorf("expected one deadlock victim, got %d", victims)
	}
	return nil
}

func repeatFor(ctx context.Context, duration time.Duration, operation func(context.Context) error) error {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	for {
		if err := operation(ctx); err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) && parent.Err() == nil {
				return nil
			}
			return err
		}
		if !pause(ctx, time.Second) {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) && parent.Err() == nil {
				return nil
			}
			return ctx.Err()
		}
	}
}
