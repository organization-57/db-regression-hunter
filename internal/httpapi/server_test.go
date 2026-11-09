package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
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
