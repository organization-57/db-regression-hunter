package analysis

import (
	"regexp"
	"strings"
)

var (
	sqlComment      = regexp.MustCompile(`--[^\n]*|/\*[\s\S]*?\*/`)
	plainLiteral    = regexp.MustCompile(`'(?:[^'\\]|'')*'`)
	escapeLiteral   = regexp.MustCompile(`(?i)\b[eub]&?'`)
	readOnlyStart   = map[string]bool{"select": true, "with": true, "show": true, "table": true, "values": true, "explain": true}
	writingWord     = regexp.MustCompile(`(?i)\b(insert|update|delete|merge|truncate|into|alter|drop|create|vacuum|reindex|cluster|grant|revoke|copy|call|do|lock|refresh|analy[sz]e|set|reset|listen|notify|prepare|execute|discard|checkpoint|load|import|comment|security)\b`)
	writingFunction = regexp.MustCompile(`(?i)\b(pg_terminate_backend|pg_cancel_backend|pg_reload_conf|set_config|pg_(try_)?advisory\w*|pg_stat_reset\w*|pg_stat_statements_reset|pg_switch_wal|pg_promote|pg_wal_\w+|pg_log_\w+|nextval|setval|pg_rotate_logfile|lo_\w+|pg_sleep\w*|dblink\w*|txid_current\w*|pg_current_xact_id\w*|pg_notify|pg_read_\w*|pg_ls_\w+|pg_create_\w+|pg_drop_\w+|query_to_xml\w*|cursor_to_xml\w*|table_to_xml\w*|ts_stat)\s*\(`)
	rowLockClause   = regexp.MustCompile(`(?i)\bfor\s+(no\s+key\s+|key\s+)?(update|share)\b`)
	dynamicSQL      = regexp.MustCompile(`(?i)\b(query_to_xml\w*|cursor_to_xml\w*|table_to_xml\w*|dblink\w*|ts_stat|execute|do)\b`)
	sessionCall     = regexp.MustCompile(`(?i)\b(?:pg_terminate_backend|pg_cancel_backend)\s*\(\s*(\d+)\s*\)`)
)

func IsReadOnlySQL(sql string) bool {
	clean := sqlComment.ReplaceAllString(sql, " ")
	if strings.ContainsAny(clean, "\"$\\") || escapeLiteral.MatchString(clean) {
		return false
	}
	clean = plainLiteral.ReplaceAllString(clean, "0")
	if strings.Contains(clean, "'") || writingWord.MatchString(clean) || writingFunction.MatchString(clean) || rowLockClause.MatchString(clean) {
		return false
	}
	statements := 0
	for _, stmt := range strings.Split(clean, ";") {
		fields := strings.Fields(stmt)
		if len(fields) == 0 {
			continue
		}
		statements++
		if !readOnlyStart[strings.ToLower(strings.TrimLeft(fields[0], "("))] {
			return false
		}
	}
	return statements > 0
}

func IsMutatingSQL(sql string) bool { return strings.TrimSpace(sql) != "" && !IsReadOnlySQL(sql) }

func targetsKnownSessions(sql string, roots map[string]bool) bool {
	clean := sqlComment.ReplaceAllString(sql, " ")
	if dynamicSQL.MatchString(plainLiteral.ReplaceAllString(clean, "0")) {
		return false
	}
	lower := strings.ToLower(sql)
	mentions := strings.Count(lower, "terminate_backend") + strings.Count(lower, "cancel_backend")
	if mentions == 0 {
		return true
	}
	if strings.ContainsAny(clean, "\"$\\") || strings.Contains(clean, "||") {
		return false
	}
	calls := sessionCall.FindAllStringSubmatch(clean, -1)
	if len(calls) != mentions {
		return false
	}
	for _, m := range calls {
		if !roots[m[1]] {
			return false
		}
	}
	return true
}
