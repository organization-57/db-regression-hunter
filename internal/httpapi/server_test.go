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
	"github.com/makeev/db-regression-hunter/internal/state"
)

func TestStatusAndMetricsTrackCollection(t *testing.T) {
	s := &state.Store{}
	h := Handler(s, time.Minute)
	request := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	status := func() state.View {
		t.Helper()
		w := request("/api/status")
		var v state.View
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if status().Healthy {
		t.Fatal("empty store cannot be healthy")
	}
	at := time.Now().UTC()
	s.Update(collector.Snapshot{At: at, LockWaiters: 2, StatsReset: &at, PostmasterStart: at, BlockingGraph: &collector.BlockingGraph{At: at, Complete: true}}, &detector.Incident{ID: "episode", Status: detector.Open})
	v := status()
	if !v.Healthy || v.Latest.BlockingGraph == nil || len(v.Incidents) != 1 {
		t.Fatal("status must contain monitoring state, graph and latest report context")
	}
	body := request("/api/status").Body.String()
	for _, field := range []string{"history", "stats_reset", "postmaster_start"} {
		if strings.Contains(body, "\""+field) {
			t.Fatalf("status exposes internal field %s", field)
		}
	}
	if !strings.Contains(request("/metrics").Body.String(), "hunter_lock_waiters 2") {
		t.Fatal("missing Prometheus metrics")
	}
	s.Failed(nil)
	if status().Healthy || !strings.Contains(request("/metrics").Body.String(), "hunter_postgres_up 0") {
		t.Fatal("collection failure must affect health")
	}
	s.Update(collector.Snapshot{At: at.Add(-2 * time.Minute)}, nil)
	if status().Healthy {
		t.Fatal("stale sample cannot be healthy")
	}
}
