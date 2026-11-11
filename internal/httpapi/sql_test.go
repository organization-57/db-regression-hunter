package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
	"github.com/makeev/db-regression-hunter/internal/state"
)

func TestSQLAPIWithIndependentIncidentsAndSourceFailure(t *testing.T) {
	store := &state.Store{}
	d := detector.New(detector.Options{BaselineSamples: 3, ConfirmSamples: 2, RecoverySamples: 3, Factor: 3})
	reg := sqlstats.NewRegressor(3, 2, 3, 5, 5)
	reg.RecoveryIntervals = 3
	tracker := &sqlstats.Tracker{Regressor: reg}
	at := time.Now().UTC()
	raw := sqlstats.Snapshot{At: at, Available: true, ServerStartedAt: at.Add(-time.Hour), ResetAt: at.Add(-time.Minute), Entries: []sqlstats.Counters{{Identity: sqlstats.Identity{DatabaseID: 1, UserID: 2, QueryID: "9223372036854775806", TopLevel: true}, Since: at.Add(-time.Minute)}}}
	observe := func(calls int64, mean float64) {
		raw.At = raw.At.Add(time.Second)
		raw.Entries[0].Calls += calls
		raw.Entries[0].TotalExecMS += float64(calls) * mean
		snapshot := collector.Snapshot{At: raw.At, SQL: tracker.Observe(raw), BlockingGraph: &collector.BlockingGraph{Complete: true}}
		store.Update(snapshot, d.Observe(snapshot)...)
	}
	h := Handler(store, time.Minute)
	request := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	sqlView := func() state.SQLView {
		t.Helper()
		var view state.SQLView
		if err := json.Unmarshal(request("/api/sql").Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	incidents := func() []detector.Incident {
		t.Helper()
		var result []detector.Incident
		if err := json.Unmarshal(request("/api/incidents").Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if request("/readyz").Code != 503 || sqlView().Healthy {
		t.Fatal("empty source is ready")
	}
	observe(0, 0)
	for range 3 {
		observe(10, 1)
	}
	for range 3 {
		observe(100, 1)
	}
	if len(incidents()) != 0 {
		t.Fatal("traffic growth created SQL incident")
	}
	observe(5, 10)
	observe(5, 10)
	opened := incidents()
	if len(opened) != 1 || opened[0].Finding != detector.FindingSQLExecutionRegression || opened[0].SQLRegression.QueryID != "9223372036854775806" || opened[0].SQLContext == nil {
		t.Fatal("SQL evidence lost in API", opened)
	}
	if !sqlView().Healthy || sqlView().Latest.ActiveRegressions != 1 {
		t.Fatal("SQL interval not exposed")
	}
	if !strings.Contains(request("/metrics").Body.String(), "hunter_sql_regressions_active 1") {
		t.Fatal("missing SQL metric")
	}
	if strings.Contains(request("/api/sql").Body.String(), "\"Episodes\"") || strings.Contains(request("/api/status").Body.String(), "\"episodes\"") {
		t.Fatal("internal episode list leaked")
	}
	raw.Available = false
	raw.Reason = "collection_failed"
	observe(0, 0)
	if sqlView().Healthy || request("/readyz").Code != 200 || request("/healthz").Code != 200 {
		t.Fatal("optional SQL failure broke core readiness")
	}
	if i := incidents()[0]; i.Status != detector.Open || i.SQLRegression.Status != "unknown" {
		t.Fatal("source failure falsely resolved SQL", i)
	}
	raw.Available = true
	observe(5, 1)
	for range 3 {
		observe(5, 1)
	}
	closed := incidents()
	if len(closed) != 1 || closed[0].ID != opened[0].ID || closed[0].Status != detector.Resolved || closed[0].ResolvedAt == nil {
		t.Fatal("SQL resolution duplicated/lost episode", closed)
	}
	if len(sqlView().History) == 0 {
		t.Fatal("missing SQL history")
	}
}
