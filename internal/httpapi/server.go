package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/state"
)

func Handler(store *state.Store, maxAge time.Duration) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !store.View(maxAge, false).Healthy {
			http.Error(w, "PostgreSQL collection unavailable or stale", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /api/sql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.SQLView(maxAge))
	})
	mux.HandleFunc("GET /api/incidents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.View(maxAge, true).Incidents)
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.View(maxAge, true))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		v := store.View(maxAge, false)
		up := 0
		if v.Healthy {
			up = 1
		}
		fmt.Fprintf(w, "# TYPE hunter_postgres_up gauge\nhunter_postgres_up %d\n# TYPE hunter_incidents_retained gauge\nhunter_incidents_retained %d\n", up, len(v.Incidents))
		fmt.Fprint(w, "# TYPE hunter_incidents gauge\n")
		for _, status := range []string{detector.Open, detector.Recovering, detector.Resolved} {
			count := 0
			for _, i := range v.Incidents {
				if i.Status == status {
					count++
				}
			}
			fmt.Fprintf(w, "hunter_incidents{status=%q} %d\n", status, count)
		}
		if v.Latest == nil {
			return
		}
		s := v.Latest
		sqlUp, intervalReady := 0, 0
		if v.Healthy && s.SQL.Available && time.Since(s.SQL.At) <= maxAge {
			sqlUp = 1
		}
		if sqlUp == 1 && s.SQL.Status == "ready" {
			intervalReady = 1
		}
		fmt.Fprintf(w, "# TYPE hunter_sql_stats_up gauge\nhunter_sql_stats_up %d\n# TYPE hunter_sql_interval_ready gauge\nhunter_sql_interval_ready %d\n# TYPE hunter_sql_regressions_active gauge\nhunter_sql_regressions_active %d\n# TYPE hunter_sql_regressions_unknown gauge\nhunter_sql_regressions_unknown %d\n", sqlUp, intervalReady, s.SQL.ActiveRegressions, s.SQL.UnknownRegressions)
		fmt.Fprintf(w, "# TYPE hunter_snapshot_timestamp_seconds gauge\nhunter_snapshot_timestamp_seconds %d\n# TYPE hunter_active_sessions gauge\nhunter_active_sessions %d\n# TYPE hunter_lock_waiters gauge\nhunter_lock_waiters %d\n# TYPE hunter_oldest_query_seconds gauge\nhunter_oldest_query_seconds %g\n", s.At.Unix(), s.Active, s.LockWaiters, s.OldestQuerySeconds)
		fmt.Fprintf(w, "# TYPE hunter_transactions_total counter\nhunter_transactions_total{status=\"commit\"} %d\nhunter_transactions_total{status=\"rollback\"} %d\n# TYPE hunter_blocks_total counter\nhunter_blocks_total{source=\"read\"} %d\nhunter_blocks_total{source=\"hit\"} %d\n# TYPE hunter_temp_bytes_total counter\nhunter_temp_bytes_total %d\n", s.Commits, s.Rollbacks, s.BlocksRead, s.BlocksHit, s.TempBytes)
		fmt.Fprintf(w, "# TYPE hunter_deadlocks_total counter\nhunter_deadlocks_total %d\n", s.Deadlocks)
	})
	return mux
}
