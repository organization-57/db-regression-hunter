package state

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

func TestSQLViewsAndLookupOwnTheirData(t *testing.T) {
	store := &Store{}
	at := time.Now()
	episode := detector.SQLRegression{Identity: sqlstats.Identity{QueryID: "42"}, Status: "active", Calls: 5}
	report := sqlstats.Report{At: at, Available: true, Status: "ready", ActiveRegressions: 1, Queries: []sqlstats.Query{{Calls: 99}}, Episodes: []sqlstats.Regression{{}}}
	store.Update(collector.Snapshot{At: at, SQL: report, Statements: sqlstats.Snapshot{Entries: []sqlstats.Counters{{Calls: 100}}}}, &detector.Incident{ID: "sql", Status: detector.Open, SQLRegression: &episode, Tables: json.RawMessage(`[{"name":"id_1"}]`), Settings: json.RawMessage(`{"work_mem":"4MB"}`)})
	episode.Calls = 999
	view := store.SQLView(time.Minute)
	if view.Latest.ActiveRegressions != 1 || len(view.Latest.Queries) != 0 || len(view.Latest.Episodes) != 0 {
		t.Fatal("SQL summary retains internal samples", view)
	}
	view.Latest.ActiveRegressions = 999
	detail, ok := store.IncidentByID("sql")
	if !ok {
		t.Fatal("missing SQL incident")
	}
	detail.SQLRegression.Calls = 777
	detail.Tables[0] = ' '
	detail.Settings[0] = ' '
	again, _ := store.IncidentByID("sql")
	if again.SQLRegression.Calls != 5 || again.Tables[0] != '[' || again.Settings[0] != '{' || store.SQLView(time.Minute).Latest.ActiveRegressions != 1 {
		t.Fatal("views share mutable evidence")
	}
	metrics := store.View(time.Minute, false)
	if len(metrics.Latest.Statements.Entries) != 0 || metrics.Incidents[0].SQLRegression != nil {
		t.Fatal("metrics retains detailed evidence")
	}
}
