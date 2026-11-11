package analysis

import "testing"

func TestReadOnlySQLClassifier(t *testing.T) {
	readOnly := []string{
		"SELECT pid, pg_blocking_pids(pid) FROM pg_stat_activity WHERE query LIKE '%UPDATE demo_shop.inventory%'",
		"SHOW work_mem",
		"SELECT name, setting FROM pg_settings WHERE name IN ('work_mem', 'deadlock_timeout');",
		"SELECT relname, n_dead_tup, last_autovacuum FROM pg_stat_user_tables",
		"SELECT locktype, mode, granted, relation::regclass FROM pg_locks -- not LOCK TABLE\n",
		"WITH w AS (SELECT * FROM pg_stat_activity) SELECT count(*) FROM w",
		"SELECT updated_at FROM demo_shop.inventory ORDER BY updated_at DESC LIMIT 5",
		"SELECT a.pid, now() - a.xact_start AS age FROM pg_stat_activity a WHERE a.state = 'idle in transaction'",
		"SELECT deadlocks, temp_files FROM pg_stat_database WHERE datname = current_database()",
	}
	for _, sql := range readOnly {
		if !IsReadOnlySQL(sql) {
			t.Errorf("read-only SQL rejected: %s", sql)
		}
	}
	writing := []string{
		"SELECT pg_terminate_backend(4127)",
		"VACUUM (VERBOSE, ANALYZE) demo_shop.inventory",
		"ANALYZE demo_shop.orders",
		"CREATE INDEX CONCURRENTLY i ON demo_shop.orders (customer_id)",
		"SET work_mem = '64MB'",
		"SELECT 1; DROP TABLE demo_shop.orders",
		"WITH d AS (DELETE FROM demo_shop.orders RETURNING id) SELECT count(*) FROM d",
		"EXPLAIN ANALYZE UPDATE demo_shop.inventory SET quantity = 0",
		"EXPLAIN (ANALYZE, BUFFERS) UPDATE demo_shop.inventory SET updated_at = now()",
		"SELECT set_config('work_mem', '1GB', false)",
		"SELECT * FROM demo_shop.inventory WHERE product_id = 1 FOR UPDATE",
		"SELECT * FROM demo_shop.inventory FOR NO KEY UPDATE SKIP LOCKED",
		"SELECT * FROM demo_shop.inventory FOR SHARE",
		"SELECT * INTO backup FROM demo_shop.orders",
		"SELECT pg_sleep(600)",
		"SELECT dblink_exec('dbname=x', 'DROP TABLE t')",
		"SELECT txid_current()",
		"SELECT pg_read_file('/etc/passwd')",
		`SELECT "pg_terminate_backend"(999)`,
		"SELECT query_to_xml('select pg_terminate' || '_backend(999)', true, true, '')",
		"EXPLAIN ANALYSE DELETE FROM demo_shop.orders",
		"EXPLAIN (ANALYSE) DELETE FROM demo_shop.orders",
		"WITH d AS (UPDATE demo_shop.orders o SET status = 'paid' RETURNING 1) SELECT count(*) FROM d",
		"SELECT $a$'$a$; DROP TABLE t; SELECT $a$'$a$",
		"SELECT E'\\''; DROP TABLE t; SELECT ''",
		"SELECT pg_stat_statements_reset()",
		"SELECT pg_try_advisory_lock(1)",
		"SELECT pg_promote()",
		"SELECT 1 INTO newtable",
		"EXPLAIN ANALYZE SELECT 1",
		"EXPLAIN UPDATE demo_shop.inventory SET updated_at = now() WHERE product_id = $1",
		"SELECT * FROM demo_shop.inventory FOR KEY SHARE",
		"",
	}
	for _, sql := range writing {
		if IsReadOnlySQL(sql) {
			t.Errorf("unsafe SQL accepted as read-only: %q", sql)
		}
	}
}
