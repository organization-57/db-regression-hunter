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

func TestReadinessAndMetricsTrackCollection(t *testing.T) {
	s := &state.Store{}
	h := Handler(s, time.Minute)
	request := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	if request("/readyz").Code != 503 {
		t.Fatal("empty store is not ready")
	}
	s.Update(collector.Snapshot{At: time.Now(), LockWaiters: 2}, nil)
	if request("/readyz").Code != 200 {
		t.Fatal("fresh sample should be ready")
	}
	if !strings.Contains(request("/metrics").Body.String(), "hunter_lock_waiters 2") {
		t.Fatal("missing metrics")
	}
	s.Failed()
	if request("/readyz").Code != 503 {
		t.Fatal("failed collection must affect readiness")
	}
	s.Update(collector.Snapshot{At: time.Now().Add(-2 * time.Minute)}, nil)
	if request("/readyz").Code != 503 {
		t.Fatal("stale sample is not ready")
	}
	if request("/healthz").Code != 200 {
		t.Fatal("liveness is independent of target")
	}
}

func TestIncidentAPIUpdatesOneEpisodeAndRetainsGraphAfterRecovery(t *testing.T) {
	store := &state.Store{}
	d := detector.New(3, 2, 3)
	at := time.Now()
	graph := collector.BlockingGraph{
		Sessions: []collector.Session{{PID: 10, State: "active"}, {PID: 20, State: "idle in transaction"}},
		Edges:    []collector.BlockingEdge{{WaiterPID: 10, BlockerPID: 20}},
	}
	observe := func(age float64, locks int) {
		at = at.Add(time.Second)
		snapshot := collector.Snapshot{At: at, OldestQuerySeconds: age, LockWaiters: locks}
		if locks > 0 {
			snapshot.Blocking = graph
		}
		store.Update(snapshot, d.Observe(snapshot))
	}
	for range 3 {
		observe(0, 0)
	}
	observe(2, 1)
	observe(3, 1)
	handler := Handler(store, time.Minute)
	incidents := func() []detector.Incident {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/incidents", nil))
		var incidents []detector.Incident
		if err := json.Unmarshal(response.Body.Bytes(), &incidents); err != nil {
			t.Fatal(err)
		}
		return incidents
	}
	opened := incidents()
	if len(opened) != 1 || opened[0].Status != detector.Active || len(opened[0].Blocking) != 2 {
		t.Fatalf("missing open incident: %+v", opened)
	}
	observe(0, 0)
	if incidents()[0].Status != detector.Active {
		t.Fatal("API prematurely resolved episode")
	}
	observe(0, 0)
	resolved := incidents()
	if len(resolved) != 1 || resolved[0].ID != opened[0].ID || resolved[0].Status != detector.Resolved || resolved[0].RecoveredAt == nil {
		t.Fatalf("missing resolution update: %+v", resolved)
	}
	if len(resolved[0].Blocking) != 2 || resolved[0].Blocking[0].Graph.Edges[0].BlockerPID != 20 {
		t.Fatal("API lost historical graph after recovery")
	}
}

func TestSQLAPIReportsReadinessHistoryAndSourceFailure(t *testing.T) {
	store := &state.Store{}
	handler := Handler(store, time.Minute)
	request := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	view := func() state.SQLView {
		t.Helper()
		var v state.SQLView
		if err := json.Unmarshal(request("/api/sql").Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := view(); v.Healthy || v.Latest != nil {
		t.Fatal("empty SQL source is healthy", v)
	}
	at := time.Now()
	store.Update(collector.Snapshot{At: at, SQL: sqlstats.Report{At: at, Available: true, Status: "warming_up"}}, nil)
	if v := view(); v.Healthy || v.Latest.Status != "warming_up" {
		t.Fatal("warming source returned a valid interval", v)
	}
	for n := range 25 {
		report := sqlstats.Report{At: at, Available: true, Status: "ready", IntervalSeconds: 10,
			Top: []sqlstats.Query{{Identity: sqlstats.Identity{QueryID: "9223372036854775806"}, Calls: int64(n), MeanExecMS: 2}}}
		store.Update(collector.Snapshot{At: at, SQL: report}, nil)
		report.Top[0].Calls = -1
	}
	if v := view(); !v.Healthy || len(v.History) != sqlstats.HistoryLimit || v.Latest.Top[0].Calls != 24 || v.Latest.Top[0].QueryID != "9223372036854775806" {
		t.Fatalf("SQL JSON/history corrupted: %+v", v)
	}
	metrics := request("/metrics").Body.String()
	if !strings.Contains(metrics, "hunter_sql_stats_up 1") || !strings.Contains(metrics, "hunter_sql_interval_ready 1") {
		t.Fatal("missing SQL readiness metrics", metrics)
	}
	store.Failed()
	if view().Healthy {
		t.Fatal("core collection failure left SQL healthy")
	}
	store.Update(collector.Snapshot{At: at, SQL: sqlstats.Report{At: at, Status: "unavailable", Reason: "extension_missing"}}, nil)
	if v := view(); v.Healthy || v.Latest.Reason != "extension_missing" || len(v.Latest.Top) != 0 {
		t.Fatal("missing source was interpreted as zero SQL load", v)
	}
	if request("/readyz").Code != http.StatusOK {
		t.Fatal("optional source broke core readiness")
	}
	if strings.Contains(request("/metrics").Body.String(), "hunter_sql_stats_up 1") {
		t.Fatal("unavailable source advertised healthy")
	}
	store.Update(collector.Snapshot{At: at, SQL: sqlstats.Report{At: at.Add(-2 * time.Minute), Available: true, Status: "ready"}}, nil)
	if view().Healthy {
		t.Fatal("stale SQL data is healthy")
	}
}
