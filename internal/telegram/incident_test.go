package telegram

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/detector"
)

func TestIncidentSummaryWindow(t *testing.T) {
	started := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	b := New("", "", "https://grafana.test/d/hunter?orgId=2")
	// The formatter must work for arbitrary incidents, including a future ID lookup.
	for _, i := range []detector.Incident{
		{ID: "first", Status: detector.Open, StartedAt: started, DetectedAt: started.Add(20 * time.Second), Findings: []detector.Finding{"lock_contention"}},
		{ID: "second", Status: detector.Resolved, StartedAt: started.Add(-time.Hour), DetectedAt: started.Add(-30 * time.Minute), Findings: []detector.Finding{"query_age_regression"}},
	} {
		message := b.IncidentSummary(i)
		prefix := FormatIncident(i) + "\n\nGrafana: "
		if !strings.HasPrefix(message, prefix) {
			t.Fatal("missing incident summary", message)
		}
		u, err := url.Parse(strings.TrimPrefix(message, prefix))
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		if q.Get("from") != strconv.FormatInt(i.StartedAt.Add(-5*time.Minute).UnixMilli(), 10) || q.Get("to") != strconv.FormatInt(i.DetectedAt.Add(5*time.Minute).UnixMilli(), 10) || q.Get("orgId") != "2" {
			t.Fatal("incorrect incident window", q)
		}
		if b.IncidentSummary(i) != message {
			t.Fatal("incident window must be stable")
		}
	}
}

func TestIncidentSummaryWithoutGrafana(t *testing.T) {
	i := detector.Incident{ID: "123", Status: detector.Open, StartedAt: time.Now(), Findings: []detector.Finding{"query_age_regression"}}
	for _, base := range []string{"", "https://%"} {
		message := New("", "", base).IncidentSummary(i)
		if strings.Contains(message, "Grafana:") || message != FormatIncident(i) {
			t.Fatal("incorrect summary without a link", message)
		}
	}
}
