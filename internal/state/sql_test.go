package state

import (
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

func TestSQLViewsAndLookupOwnTheirData(t *testing.T) {
	store := &Store{}
	at := time.Now()
	factor := 10.0
	q := sqlstats.Query{Identity: sqlstats.Identity{QueryID: "42"}, Calls: 5, Comparison: sqlstats.Comparison{ExecFactor: &factor}}
	episode := sqlstats.Regression{Identity: q.Identity, Status: "active", Current: q}
	report := sqlstats.Report{At: at, Available: true, Status: "ready", Top: []sqlstats.Query{q}, Regressions: []sqlstats.Regression{episode}, Episodes: []sqlstats.Regression{episode}}
	context := &sqlstats.Context{Before: []sqlstats.Report{report}}
	store.Update(collector.Snapshot{At: at, SQL: report, Statements: sqlstats.Snapshot{Entries: []sqlstats.Counters{{Calls: 100}}}}, &detector.Incident{ID: "sql", Status: detector.Open, SQLRegression: &episode, SQLContext: context})
	factor = 999
	report.Top[0].Calls = 999
	view := store.SQLView(time.Minute)
	if view.Latest.Top[0].Calls != 5 || *view.Latest.Top[0].Comparison.ExecFactor != 10 || len(view.Latest.Episodes) != 0 {
		t.Fatal("SQL view aliases input/raw data", view)
	}
	*view.Latest.Top[0].Comparison.ExecFactor = 888
	view.History[0].Top[0].Calls = 888
	detail, ok := store.IncidentByID("sql")
	if !ok {
		t.Fatal("SQL incident not found")
	}
	*detail.SQLRegression.Current.Comparison.ExecFactor = 777
	detail.SQLContext.Before[0].Top[0].Calls = 777
	again, _ := store.IncidentByID("sql")
	if *again.SQLRegression.Current.Comparison.ExecFactor != 10 || again.SQLContext.Before[0].Top[0].Calls != 5 || store.SQLView(time.Minute).History[0].Top[0].Calls != 5 {
		t.Fatal("views or ID lookup mutate retained SQL evidence")
	}
	metrics := store.View(time.Minute, false)
	if len(metrics.Latest.SQL.Top) != 0 || len(metrics.Latest.SQL.Regressions) != 0 || len(metrics.Latest.Statements.Entries) != 0 || metrics.Incidents[0].SQLRegression != nil {
		t.Fatal("scalar metrics view retained SQL reports")
	}
}
