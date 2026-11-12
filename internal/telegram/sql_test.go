package telegram

import (
	"strings"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

func TestSQLIncidentSummaryPreservesLookupFormatAndGrafanaWindow(t *testing.T) {
	at := time.Now().UTC()
	i := detector.Incident{ID: "sql-42", Status: detector.Open, StartedAt: at, DetectedAt: at.Add(time.Minute), Findings: []detector.Finding{detector.FindingSQLExecutionRegression},
		Trigger:       detector.Trigger{Metric: "sql_mean_exec_ms", Observed: 20, Baseline: 1, Threshold: 6},
		SQLRegression: &detector.SQLRegression{Identity: sqlstats.Identity{QueryID: "42", DatabaseID: 1, UserID: 2}, Status: "unknown", Reason: "insufficient_calls", LastObservedAt: at, MeanExecMS: 20, CallsPerSecond: 5, BaselineCallsPerSecond: 5}}

	b := New("", "", "https://grafana.test/d/hunter?orgId=2")
	text := b.IncidentSummary(i)
	for _, want := range []string{"Факты: замедление SQL", "SQL 42", "20.00 ms/вызов", "baseline: 1.00", "Недостаточно данных, чтобы оценить восстановление", "Ссылка на окно в Grafana", "from=", "to=", "orgId=2"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
	if len([]rune(FormatIncident(i))) > 3000 {
		t.Fatal("SQL formatting exceeded message budget")
	}
	for _, status := range []string{"active", "recovering", "resolved", "unknown"} {
		i.SQLRegression.Status = status
		text := b.IncidentSummary(i)
		for _, unwanted := range []string{"БД 1", "роль 2", "SQL-состояние", "insufficient_calls", "latency приложения"} {
			if strings.Contains(text, unwanted) {
				t.Fatalf("unexpected %q in %s", unwanted, text)
			}
		}
		if strings.Contains(text, "Недостаточно данных") != (status == "unknown") {
			t.Fatalf("incorrect missing-data warning for %s: %s", status, text)
		}
	}
}
