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

func TestQueryContextPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("DEMO_TEST_DATABASE_URL")
	monitorDSN := os.Getenv("DEMO_TEST_MONITOR_DATABASE_URL")
	if dsn == "" || monitorDSN == "" {
		t.Skip("set separate application and monitoring DSNs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A dedicated schema avoids touching the demo workload or resetting statistics.
	_, err = db.ExecContext(ctx, `CREATE SCHEMA hunter_context_test;
CREATE TABLE hunter_context_test.private_customers (private_id bigint PRIMARY KEY, private_email varchar(80) NOT NULL UNIQUE);
INSERT INTO hunter_context_test.private_customers VALUES (1,'never-export@example.test');
ANALYZE hunter_context_test.private_customers;
GRANT USAGE ON SCHEMA hunter_context_test TO hunter;
GRANT SELECT ON ALL TABLES IN SCHEMA hunter_context_test TO hunter;`)
	if err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DROP SCHEMA hunter_context_test CASCADE`)
	var email string
	if err = db.QueryRowContext(ctx, `SELECT private_email FROM hunter_context_test.private_customers WHERE private_id=$1`, 1).Scan(&email); err != nil {
		t.Fatal(err)
	}
	monitor, err := New(monitorDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()
	var id sqlstats.Identity
	// Reading as the application role selects the precise entry without resets.
	err = db.QueryRowContext(ctx, `SELECT dbid,userid,queryid::text,toplevel FROM pg_stat_statements
WHERE userid=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND query LIKE 'SELECT private_email FROM hunter_context_test.private_customers WHERE private_id=%' AND toplevel LIMIT 1`).Scan(&id.DatabaseID, &id.UserID, &id.QueryID, &id.TopLevel)
	if err != nil {
		t.Fatal(err)
	}
	batch := monitor.QueryContexts(ctx, []QueryTarget{{Statement: &id}})
	data := batch.Details[0]
	if !strings.Contains(string(data), "private_email") || !strings.Contains(string(data), "hunter_context_test") {
		t.Fatal("local SQL was anonymized", string(data))
	}
	if strings.Contains(string(data), "never-export") {
		t.Fatal("table rows must not be collected")
	}

	details := decodeQueryContext(t, batch, 0)
	if details.SQL == "" || details.Plan == nil || len(details.Tables) != 1 || len(details.Reasons) != 0 || details.Settings["work_mem"] == "" {
		t.Fatalf("incomplete evidence: %s", data)
	}
	table := details.Tables[0]
	if table["estimated_rows"].(float64) != 1 || table["total_bytes"].(float64) <= 0 {
		t.Fatal("missing table metadata", table)
	}
	t.Run("blocking_sessions", func(t *testing.T) {
		root, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Rollback()
		var rootPID, waiterPID int
		if err = root.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&rootPID); err != nil {
			t.Fatal(err)
		}
		if _, err = root.ExecContext(ctx, `UPDATE hunter_context_test.private_customers SET private_email='root-secret@example.test' WHERE private_id=1`); err != nil {
			t.Fatal(err)
		}
		// The last statement is deliberately unrelated to the acquired row lock.
		var marker int
		if err = root.QueryRowContext(ctx, `SELECT 314159 AS private_marker`).Scan(&marker); err != nil {
			t.Fatal(err)
		}
		waiter, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer waiter.Rollback()
		if err = waiter.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&waiterPID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := waiter.ExecContext(ctx, `UPDATE hunter_context_test.private_customers SET private_email='waiter-secret@example.test' WHERE private_id=1`)
			done <- err
		}()
		defer func() { root.Rollback(); <-done }()
		var snapshot Snapshot
		deadline := time.Now().Add(5 * time.Second)
		for {
			snapshot, err = monitor.Collect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			blocked := false
			for _, node := range snapshot.BlockingGraph.Nodes {
				if node.PID == waiterPID && len(node.BlockedBy) > 0 {
					blocked = true
				}
			}
			if blocked {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("waiter did not block")
			}
			time.Sleep(20 * time.Millisecond)
		}
		targets := make([]QueryTarget, 2)
		for _, node := range snapshot.BlockingGraph.Nodes {
			index := -1
			if node.PID == rootPID {
				index = 0
			}
			if node.PID == waiterPID {
				index = 1
			}
			if index < 0 {
				continue
			}
			targets[index] = QueryTarget{PID: node.PID, BackendStart: node.BackendStart, QueryStart: node.QueryStart, TransactionStart: node.TransactionStart, State: node.State}.Clone()
		}
		if targets[0].State != "idle in transaction" || targets[1].State != "active" {
			t.Fatal("wrong captured states", targets)
		}
		live, err := monitor.LongRunning(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, session := range live {
			if session.PID == waiterPID {
				found = true
				if session.BackendStart == nil || session.QueryStart == nil || session.TransactionStart == nil || session.ObservedAt.IsZero() {
					t.Fatal("missing live session provenance", session)
				}
			}
		}
		if !found {
			t.Fatal("blocked active session missing from long-running sample")
		}
		batch := monitor.QueryContexts(ctx, targets)
		contexts := batch.Details
		rootContext := decodeQueryContext(t, batch, 0)
		waiterContext := decodeQueryContext(t, batch, 1)
		var shared []map[string]any
		if err = json.Unmarshal(batch.Tables, &shared); err != nil || len(shared) != 1 {
			t.Fatal("table metadata was not deduplicated", string(batch.Tables), err)
		}

		if rootContext.QuerySource != "last_statement" || waiterContext.QuerySource != "active_statement" || rootContext.TableScope != "plan_and_session_locks" {
			t.Fatal("missing statement provenance", rootContext, waiterContext)
		}
		if len(rootContext.Locks) == 0 || len(waiterContext.Locks) == 0 || len(rootContext.Tables) != 1 || len(waiterContext.Tables) != 1 {
			t.Fatalf("missing locks or catalog evidence: %s %s", contexts[0], contexts[1])
		}
		if rootContext.Tables[0]["name"] != waiterContext.Tables[0]["name"] || rootContext.Tables[0]["schema"] != waiterContext.Tables[0]["schema"] {
			t.Fatal("participant pseudonyms do not match")
		}
		if waiterContext.Plan != nil || !strings.Contains(string(contexts[1]), "explain_unavailable") || waiterContext.Settings["work_mem"] == "" {
			t.Fatal("failed EXPLAIN must not abort catalog/settings collection", string(contexts[1]))
		}
		if !strings.Contains(rootContext.SQL, "314159") || !strings.Contains(waiterContext.SQL, "waiter-secret@example.test") {
			t.Fatal("local context lost SQL values")
		}

		// Reused PIDs, changed queries and changed transactions must not match.
		for _, field := range []string{"backend", "query", "transaction"} {
			stale := targets[0].Clone()
			switch field {
			case "backend":
				at := stale.BackendStart.Add(time.Second)
				stale.BackendStart = &at
			case "query":
				at := stale.QueryStart.Add(time.Second)
				stale.QueryStart = &at
			case "transaction":
				at := stale.TransactionStart.Add(time.Second)
				stale.TransactionStart = &at
			}
			data := monitor.QueryContexts(ctx, []QueryTarget{stale}).Details[0]
			var missing queryContext
			json.Unmarshal(data, &missing)
			if missing.SQL != "" || !strings.Contains(string(data), "session_changed_or_unavailable") {
				t.Fatal("stale session was attributed to incident", string(data))
			}
		}
	})
	if _, err = db.ExecContext(ctx, `REVOKE SELECT ON hunter_context_test.private_customers FROM hunter`); err != nil {
		t.Fatal(err)
	}
	data = monitor.QueryContexts(ctx, []QueryTarget{{Statement: &id}}).Details[0]
	if !strings.Contains(string(data), "explain_unavailable") || strings.Contains(string(data), "permission denied") {
		t.Fatalf("permission failure leaked server text: %s", data)
	}
}

// Resolve references just as a consumer would, checking the compact wire format.
func decodeQueryContext(t *testing.T, batch QueryBatch, index int) queryContext {
	t.Helper()
	var result queryContext
	if err := json.Unmarshal(batch.Details[index], &result); err != nil {
		t.Fatal(err)
	}
	if len(batch.Settings) > 0 {
		if err := json.Unmarshal(batch.Settings, &result.Settings); err != nil {
			t.Fatal(err)
		}
	}
	var tables []map[string]any
	if len(batch.Tables) > 0 {
		if err := json.Unmarshal(batch.Tables, &tables); err != nil {
			t.Fatal(err)
		}
	}
	for _, ref := range result.TableRefs {
		found := false
		for _, table := range tables {
			if RelationRef(table["schema"].(string), table["name"].(string)) == ref {
				result.Tables = append(result.Tables, table)
				found = true
				break
			}
		}
		if !found {
			t.Fatal("dangling table reference", ref)
		}
	}
	var wire map[string]any
	json.Unmarshal(batch.Details[index], &wire)
	if _, ok := wire["settings"]; ok {
		t.Fatal("per-query settings duplicate shared context")
	}
	for _, table := range result.TableRefs {
		if table == "" {
			t.Fatal("empty table reference")
		}
	}
	return result
}
