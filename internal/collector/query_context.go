package collector

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

type queryContext struct {
	At          time.Time         `json:"at"`
	SQL         string            `json:"sql,omitempty"`
	PlanKind    string            `json:"plan_kind,omitempty"`
	Plan        map[string]any    `json:"plan,omitempty"`
	Tables      []map[string]any  `json:"-"`
	Settings    map[string]string `json:"-"`
	TableRefs   []string          `json:"tables,omitempty"`
	Reasons     []string          `json:"incomplete_reasons,omitempty"`
	QuerySource string            `json:"query_source"`
	TableScope  string            `json:"table_scope"`
	Locks       []map[string]any  `json:"locks,omitempty"`
}

// Session timestamps prevent attributing a reused PID or another query/transaction
// on the same backend to the observed blocking graph.
type QueryTarget struct {
	Statement        *sqlstats.Identity `json:"-"`
	PID              int                `json:"pid,omitempty"`
	BackendStart     *time.Time         `json:"backend_start,omitempty"`
	QueryStart       *time.Time         `json:"query_start,omitempty"`
	TransactionStart *time.Time         `json:"transaction_start,omitempty"`
	State            string             `json:"-"`
}

func (t QueryTarget) Clone() QueryTarget {
	if t.Statement != nil {
		id := *t.Statement
		t.Statement = &id
	}
	t.BackendStart = cloneTime(t.BackendStart)
	t.QueryStart = cloneTime(t.QueryStart)
	t.TransactionStart = cloneTime(t.TransactionStart)
	return t
}

// QueryBatch shares table metadata and settings between participants.
type QueryBatch struct {
	Details  []json.RawMessage
	Tables   json.RawMessage
	Settings json.RawMessage
}

// QueryContexts uses one ephemeral name dictionary and one table cache per batch.
func (p *Postgres) QueryContexts(parent context.Context, targets []QueryTarget) QueryBatch {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	a := anonymizer{}
	cache := map[string]map[string]any{}
	seen := map[string]bool{}
	var tables []json.RawMessage
	var batch QueryBatch
	tableBytes := 0
	for _, target := range targets {
		result := p.queryContext(ctx, target, a, cache)
		for _, table := range result.Tables {
			ref := table["schema"].(string) + "." + table["name"].(string)
			if !seen[ref] {
				data, _ := json.Marshal(table)
				if tableBytes+len(data) > 1024*1024 {
					result.Reasons = append(result.Reasons, "context_limit")
					continue
				}
				seen[ref] = true
				tableBytes += len(data)
				tables = append(tables, data)
			}
			result.TableRefs = append(result.TableRefs, ref)
		}
		if len(batch.Settings) == 0 && len(result.Settings) > 0 {
			batch.Settings, _ = json.Marshal(result.Settings)
		}
		data, _ := json.Marshal(result)
		if len(data) > 1024*1024 {
			result.Plan = nil
			result.Reasons = append(result.Reasons, "context_limit")
			data, _ = json.Marshal(result)
		}
		batch.Details = append(batch.Details, data)
	}
	if len(tables) > 0 {
		batch.Tables, _ = json.Marshal(tables)
	}
	return batch
}

func (p *Postgres) queryContext(ctx context.Context, target QueryTarget, a anonymizer, cache map[string]map[string]any) queryContext {
	result := queryContext{At: time.Now().UTC(), TableScope: "plan_relations", QuerySource: "normalized_statement"}
	finish := func(reason string) queryContext {
		if reason != "" {
			result.Reasons = append(result.Reasons, reason)
		}
		return result
	}

	conn, err := p.db.Conn(ctx)
	if err != nil {
		return finish("collection_failed")
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return finish("collection_failed")
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL statement_timeout='1500ms'; SET LOCAL lock_timeout='200ms'`); err != nil {
		return finish("collection_failed")
	}
	var raw string
	relations := map[string][2]string{}
	if target.Statement != nil {
		id := target.Statement
		var schema string
		err = tx.QueryRowContext(ctx, `SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='pg_stat_statements'`).Scan(&schema)
		if err != nil {
			return finish(statementError(err))
		}
		// pg_stat_statements returns a representative query, not bindings.
		err = tx.QueryRowContext(ctx, `SELECT query FROM `+pgx.Identifier{schema}.Sanitize()+`.pg_stat_statements(true)
WHERE dbid=$1 AND userid=$2 AND queryid=$3::bigint AND toplevel=$4
AND dbid=(SELECT oid FROM pg_database WHERE datname=current_database())`, id.DatabaseID, id.UserID, id.QueryID, id.TopLevel).Scan(&raw)
		if err != nil {
			return finish("query_unavailable")
		}
	} else {
		result.TableScope = "plan_and_session_locks"
		result.QuerySource = "active_statement"
		if target.State != "active" {
			result.QuerySource = "last_statement"
		}
		if target.PID == 0 || target.BackendStart == nil || target.QueryStart == nil {
			return finish("session_unavailable")
		}
		var local bool
		var textLimit int
		err = tx.QueryRowContext(ctx, `SELECT query, datid=(SELECT oid FROM pg_database WHERE datname=current_database()), pg_size_bytes(current_setting('track_activity_query_size'))
FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2 AND query_start=$3
AND xact_start IS NOT DISTINCT FROM $4::timestamptz AND state=$5`, target.PID, target.BackendStart, target.QueryStart, target.TransactionStart, target.State).Scan(&raw, &local, &textLimit)
		if err != nil {
			return finish("session_changed_or_unavailable")
		}
		if !local {
			result.SQL, err = a.sql(raw)
			if err != nil {
				return finish("unsupported_sql")
			}
			return finish("different_database")
		}
		if len(raw) >= textLimit-4 {
			result.Reasons = append(result.Reasons, "query_may_be_truncated")
		}
		// These are session locks, not proof that the last SQL acquired them.
		rows, err := tx.QueryContext(ctx, `SELECT l.locktype,l.mode,l.granted,n.nspname,c.relname
FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
LEFT JOIN pg_class c ON c.oid=l.relation AND c.relkind IN ('r','p','m','v','f') AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
LEFT JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE l.pid=$1 AND a.backend_start=$2 AND a.query_start=$3 AND a.xact_start IS NOT DISTINCT FROM $4::timestamptz AND a.state=$5
ORDER BY l.locktype,l.mode,n.nspname,c.relname LIMIT 129`, target.PID, target.BackendStart, target.QueryStart, target.TransactionStart, target.State)
		if err != nil {
			return finish("locks_unavailable")
		}
		for rows.Next() {
			var kind, mode string
			var granted bool
			var schema, table sql.NullString
			if err = rows.Scan(&kind, &mode, &granted, &schema, &table); err != nil {
				break
			}
			lock := map[string]any{"type": kind, "mode": mode, "granted": granted}
			if schema.Valid && table.Valid {
				lock["table"] = a.name(schema.String) + "." + a.name(table.String)
				relations[schema.String+"\x00"+table.String] = [2]string{schema.String, table.String}
			}
			result.Locks = append(result.Locks, lock)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return finish("locks_unavailable")
		}
		if len(result.Locks) > 128 {
			result.Locks = result.Locks[:128]
			result.Reasons = append(result.Reasons, "lock_limit")
		}
	}
	result.SQL, err = a.sql(raw)
	var plan map[string]any
	var reason string
	if err != nil {
		reason = "unsupported_sql"
	} else {
		plan, reason = readPlan(ctx, conn, tx, raw, result.SQL)
	}
	if reason != "" {
		result.Reasons = append(result.Reasons, reason)
	}
	// Relations in the plan include expanded views and partitions. Eliminated
	// relations are not available here; do not pretend this is the SQL's full AST.
	var collect func(map[string]any)
	collect = func(node map[string]any) {
		schema, _ := node["Schema"].(string)
		table, _ := node["Relation Name"].(string)
		if schema != "" && table != "" {
			relations[schema+"\x00"+table] = [2]string{schema, table}
		}
		children, _ := node["Plans"].([]any)
		for _, child := range children {
			if n, ok := child.(map[string]any); ok {
				collect(n)
			}
		}
	}
	if plan != nil {
		result.PlanKind = "generic_monitor_role"
		collect(plan)
		result.Plan = a.plan(plan)
	}
	keys := make([]string, 0, len(relations))
	for key := range relations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > 32 {
		keys = keys[:32]
		result.Reasons = append(result.Reasons, "table_limit")
	}
	for _, key := range keys {
		r := relations[key]
		table := cache[key]
		if table == nil {
			var err error
			table, err = readTable(ctx, tx, r[0], r[1], a)
			if err != nil {
				return finish("table_metadata_unavailable")
			}
			cache[key] = table
		}
		result.Tables = append(result.Tables, table)
	}
	rows, err := tx.QueryContext(ctx, `SELECT name, current_setting(name) FROM pg_settings WHERE name IN
('server_version_num','work_mem','effective_cache_size','random_page_cost','seq_page_cost','effective_io_concurrency','max_parallel_workers_per_gather','jit','default_statistics_target') ORDER BY name`)
	if err != nil {
		return finish("settings_unavailable")
	}
	defer rows.Close()
	result.Settings = map[string]string{}
	for rows.Next() {
		var name, value string
		if rows.Scan(&name, &value) != nil {
			return finish("settings_unavailable")
		}
		result.Settings[name] = value
	}
	if rows.Err() != nil {
		return finish("settings_unavailable")
	}
	return finish("")
}

func readPlan(ctx context.Context, conn *sql.Conn, tx *sql.Tx, raw, safe string) (map[string]any, string) {
	// Lexing has already rejected stacked statements and ambiguous quoting.
	first := strings.Fields(safe)
	if len(first) == 0 || !strings.Contains(" select with insert update delete ", " "+first[0]+" ") {
		return nil, "unsupported_statement"
	}
	if _, err := tx.ExecContext(ctx, "SAVEPOINT query_plan"); err != nil {
		return nil, "explain_unavailable"
	}
	var data []byte
	// Bypass pgx's parameter interpolation: $1 belongs to GENERIC_PLAN itself.
	err := conn.Raw(func(driverConn any) error {
		results, err := driverConn.(*stdlib.Conn).Conn().PgConn().Exec(ctx, "EXPLAIN (GENERIC_PLAN, VERBOSE, FORMAT JSON) "+raw).ReadAll()
		if err != nil {
			return err
		}
		if len(results) != 1 || len(results[0].Rows) != 1 || len(results[0].Rows[0]) != 1 {
			return errors.New("invalid_plan")
		}
		data = results[0].Rows[0][0]
		return nil
	})
	if err != nil {
		// A permission/lock error must not prevent reading catalog metadata.
		tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT query_plan")
		return nil, "explain_unavailable"
	}
	if len(data) > 512*1024 {
		return nil, "plan_limit"
	}
	var plans []struct {
		Plan map[string]any `json:"Plan"`
	}
	if json.Unmarshal(data, &plans) != nil || len(plans) != 1 {
		return nil, "invalid_plan"
	}
	return plans[0].Plan, ""
}

func readTable(ctx context.Context, tx *sql.Tx, schema, name string, a anonymizer) (map[string]any, error) {
	var oid uint32
	var data []byte
	err := tx.QueryRowContext(ctx, `SELECT c.oid, json_build_object(
'estimated_rows',c.reltuples,'heap_bytes',pg_relation_size(c.oid),'total_bytes',pg_total_relation_size(c.oid),
'index_bytes',pg_indexes_size(c.oid),'live_tuples',s.n_live_tup,'dead_tuples',s.n_dead_tup,
'modifications_since_analyze',s.n_mod_since_analyze,'last_analyze',s.last_analyze,'last_autoanalyze',s.last_autoanalyze,
'last_vacuum',s.last_vacuum,'last_autovacuum',s.last_autovacuum)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_stat_all_tables s ON s.relid=c.oid
WHERE n.nspname=$1 AND c.relname=$2`, schema, name).Scan(&oid, &data)
	if err != nil {
		return nil, err
	}
	var table map[string]any
	if err = json.Unmarshal(data, &table); err != nil {
		return nil, err
	}
	table["schema"], table["name"] = a.name(schema), a.name(name)
	// No samples, histograms, most-common values, defaults or comments.
	rows, err := tx.QueryContext(ctx, `SELECT a.attname, format_type(a.atttypid,a.atttypmod),a.attnotnull,
s.null_frac,s.n_distinct,s.avg_width,s.correlation
FROM pg_attribute a LEFT JOIN pg_stats s ON s.schemaname=$2 AND s.tablename=$3 AND s.attname=a.attname AND NOT s.inherited
WHERE a.attrelid=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum LIMIT 257`, oid, schema, name)
	if err != nil {
		return nil, err
	}
	columns := []map[string]any{}
	for rows.Next() {
		var col, typ string
		var notnull bool
		var nulls, distinct, correlation sql.NullFloat64
		var width sql.NullInt64
		if err = rows.Scan(&col, &typ, &notnull, &nulls, &distinct, &width, &correlation); err != nil {
			break
		}
		var safeType string
		safeType, err = a.tokens(typ, false)
		if err != nil {
			break
		}
		c := map[string]any{"name": a.name(col), "type": safeType, "not_null": notnull}
		if nulls.Valid {
			c["null_fraction"] = nulls.Float64
		}
		if distinct.Valid {
			c["distinct_estimate"] = distinct.Float64
		}
		if width.Valid {
			c["avg_width"] = width.Int64
		}
		if correlation.Valid {
			c["correlation"] = correlation.Float64
		}
		columns = append(columns, c)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	table["columns"] = columns
	if len(columns) > 256 {
		table["columns"] = columns[:256]
		table["columns_truncated"] = true
	}
	rows, err = tx.QueryContext(ctx, `SELECT pg_get_indexdef(indexrelid),indisvalid FROM pg_index WHERE indrelid=$1 ORDER BY indexrelid LIMIT 65`, oid)
	if err != nil {
		return nil, err
	}
	indexes := []map[string]any{}
	for rows.Next() {
		var definition string
		var valid bool
		if err = rows.Scan(&definition, &valid); err != nil {
			break
		}
		var safe string
		safe, err = a.sql(definition)
		if err != nil {
			break
		}
		indexes = append(indexes, map[string]any{"definition": safe, "valid": valid})
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	table["indexes"] = indexes
	if len(indexes) > 64 {
		table["indexes"] = indexes[:64]
		table["indexes_truncated"] = true
	}
	rows, err = tx.QueryContext(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=$1 ORDER BY oid LIMIT 65`, oid)
	if err != nil {
		return nil, err
	}
	constraints := []string{}
	for rows.Next() {
		var definition string
		if err = rows.Scan(&definition); err != nil {
			break
		}
		var safe string
		safe, err = a.sql(definition)
		if err != nil {
			break
		}
		constraints = append(constraints, safe)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	table["constraints"] = constraints
	if len(constraints) > 64 {
		table["constraints"] = constraints[:64]
		table["constraints_truncated"] = true
	}
	return table, nil
}

// Explicit fields only: EXPLAIN extensions can add arbitrary strings. Expressions
// go through the same lexer as SQL; unknown fields never pass through unchanged.
func (a anonymizer) plan(node map[string]any) map[string]any {
	out := map[string]any{}
	keys := make([]string, 0, len(node))
	for k := range node {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := node[k]
		switch k {
		case "Startup Cost", "Total Cost", "Plan Rows", "Plan Width", "Workers Planned", "Parallel Aware", "Async Capable", "Inner Unique":
			switch v.(type) {
			case float64, bool:
				out[k] = v
			}
		case "Relation Name", "Schema", "Alias", "Index Name", "CTE Name":
			if s, ok := v.(string); ok {
				out[k] = a.name(s)
			}
		case "Node Type", "Join Type", "Strategy", "Partial Mode", "Scan Direction", "Parent Relationship", "Operation":
			if s, ok := v.(string); ok {
				// Names of custom scan providers/node types are not trusted.
				const enums = "|Seq Scan|Index Scan|Index Only Scan|Bitmap Heap Scan|Bitmap Index Scan|BitmapAnd|BitmapOr|Tid Scan|Tid Range Scan|Nested Loop|Hash Join|Merge Join|Hash|Sort|Incremental Sort|Aggregate|Group|Limit|Result|Append|Merge Append|Gather|Gather Merge|Materialize|Memoize|Unique|WindowAgg|Subquery Scan|CTE Scan|WorkTable Scan|Function Scan|Values Scan|Recursive Union|SetOp|LockRows|ModifyTable|Foreign Scan|Custom Scan|Sample Scan|Inner|Left|Right|Full|Semi|Anti|Plain|Sorted|Hashed|Mixed|Simple|Partial|Finalize|Forward|Backward|NoMovement|Outer|Member|Subquery|InitPlan|SubPlan|Insert|Update|Delete|Merge|"
				if strings.Contains(enums, "|"+s+"|") {
					out[k] = s
				} else {
					out[k] = "redacted"
				}
			}
		case "Filter", "Index Cond", "Recheck Cond", "Hash Cond", "Merge Cond", "Join Filter", "One-Time Filter", "Function Call":
			if s, ok := v.(string); ok {
				if safe, err := a.sql(s); err == nil {
					out[k] = safe
				} else {
					out[k] = "redacted"
				}
			}
		case "Output", "Sort Key", "Group Key", "Hash Key", "Presorted Key", "Cache Key":
			if list, ok := v.([]any); ok {
				safe := []string{}
				for _, item := range list {
					if s, ok := item.(string); ok {
						if x, err := a.sql(s); err == nil {
							safe = append(safe, x)
						} else {
							safe = append(safe, "redacted")
						}
					}
				}
				out[k] = safe
			}
		case "Plans":
			if list, ok := v.([]any); ok {
				children := []map[string]any{}
				for _, item := range list {
					if n, ok := item.(map[string]any); ok {
						children = append(children, a.plan(n))
					}
				}
				out[k] = children
			}
		}
	}
	return out
}
