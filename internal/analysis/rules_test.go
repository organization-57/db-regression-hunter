package analysis

import (
	"strings"
	"testing"

	"github.com/makeev/db-regression-hunter/internal/evidence"
)

func signals(findings ...string) evidence.Package {
	p := evidence.Package{Schema: evidence.Schema, Metrics: []evidence.Metric{
		{ID: "M1", Name: "oldest_active_query_age", Change: evidence.Change{Baseline: f(0.3), Incident: f(40)}},
		{ID: "M2", Name: "active_sessions", Change: evidence.Change{Baseline: f(3), Incident: f(11)}},
		{ID: "M3", Name: "lock_waiting_sessions", Change: evidence.Change{Baseline: f(0), Incident: f(0)}},
		{ID: "M4", Name: "commits_per_second", Change: evidence.Change{Baseline: f(14), Incident: f(13)}},
		{ID: "M5", Name: "deadlocks_per_second", Change: evidence.Change{Baseline: f(0), Incident: f(0.2)}},
		{ID: "M6", Name: "temp_bytes_per_second", Change: evidence.Change{Baseline: f(0), Incident: f(9e6)}},
	}}
	for n, finding := range findings {
		p.Incidents = append(p.Incidents, evidence.Incident{ID: "I" + string(rune('1'+n)), IncidentID: finding, Findings: []string{finding}, Status: "open"})
	}
	return p
}

func TestRulesExplainEachScenarioWithinTheContract(t *testing.T) {
	stale := pkg()
	stale.LockGraphCurrent = false
	table := pkg()
	table.Locks[0].WaiterWaitEvents = []string{"Lock:relation"}
	table.Locks[0].BlockingState = "idle in transaction"
	surge := signals("active_sessions_surge")
	surge.Sessions = []evidence.Session{{ID: "S1", PID: 90, State: "active", QueryAgeSeconds: 40}}
	busy := signals("active_sessions_surge")
	busy.Metrics[3].Incident = f(40)
	report := signals("query_age_regression")
	report.Sessions = []evidence.Session{{ID: "S1", PID: 77, State: "active", WaitEvent: "Timeout:PgSleep", QueryAgeSeconds: 41}}
	slowSQL := signals("sql_execution_regression")
	slowSQL.Statements = []evidence.Statement{{ID: "Q1", QueryID: "-4812771253", MeanExecMS: evidence.Change{Baseline: f(0.6), Incident: f(30)},
		CallsPerSecond: evidence.Change{Baseline: f(40), Incident: f(41)}, SharedReadsPerCall: 400}}
	hotSQL := signals("sql_execution_regression")
	hotSQL.Statements = []evidence.Statement{{ID: "Q1", QueryID: "-4812771253", MeanExecMS: evidence.Change{Baseline: f(0.6), Incident: f(3)},
		CallsPerSecond: evidence.Change{Baseline: f(40), Incident: f(400)}}}
	cases := []struct {
		name     string
		p        evidence.Package
		category string
		sql      string
	}{
		{"row lock", pkg(), "long_transaction", "SELECT pg_terminate_backend(4127)"},
		{"stale graph", stale, "long_transaction", ""},
		{"table lock", table, "blocking_ddl", "SELECT pg_terminate_backend(4127)"},
		{"deadlock", signals("deadlock", "query_age_regression"), "deadlock", ""},
		{"temp spill", signals("temp_file_growth"), "temp_spill", ""},
		{"session burst", surge, "connection_saturation", ""},
		{"traffic", busy, "load_growth", ""},
		{"slow report", report, "slow_query", ""},
		{"slow statement", slowSQL, "slow_query", ""},
		{"hot statement", hotSQL, "load_growth", ""},
		{"nothing", signals("query_age_regression"), "unknown", ""},
	}
	for _, c := range cases {
		a := Rules(c.p)
		v := check(&a, c.p)
		if len(v.errors) > 0 || len(v.warnings) > 0 {
			t.Errorf("%s: the rules broke the contract: %v %v", c.name, v.errors, v.warnings)
			continue
		}
		if got := a.RootCauses[0].Category; got != c.category {
			t.Errorf("%s: category %s, want %s", c.name, got, c.category)
		}
		if got := a.Recommendations[0].SQL; got != c.sql || (got != "" && !a.Recommendations[0].RequiresApproval) {
			t.Errorf("%s: recommendation SQL %q approval %v", c.name, got, a.Recommendations[0].RequiresApproval)
		}
		if !strings.Contains(strings.Join(a.Assumptions, " "), "без LLM") {
			t.Errorf("%s: the answer must say it was made without the model", c.name)
		}
	}
}
