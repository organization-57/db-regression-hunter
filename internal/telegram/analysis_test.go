package telegram

import (
	"strings"
	"testing"

	"github.com/makeev/db-regression-hunter/internal/analysis"
	"github.com/makeev/db-regression-hunter/internal/evidence"
)

func TestFormatAnalysisShowsFactsInsteadOfIDs(t *testing.T) {
	base, now := 0.0, 6.0
	p := &evidence.Package{
		Metrics: []evidence.Metric{{ID: "M3", Name: "lock_waiting_sessions", Change: evidence.Change{Baseline: &base, Incident: &now}}},
		Locks: []evidence.Lock{{ID: "L1", BlockingPID: 4127, BlockingApplication: "shop", BlockingState: "idle in transaction", TransactionAgeSeconds: 34, BlockedTotal: 7,
			BlockingQuery: "UPDATE demo_shop.inventory SET updated_at=now() WHERE product_id=$1"}},
	}
	p.Incidents = []evidence.Incident{{ID: "I1", Finding: "lock_contention"}, {ID: "I2", Finding: "sql_execution_regression"}}
	r := analysis.Result{Status: analysis.Done, Model: "deepseek-ai/DeepSeek-V4-Flash-0731", LatencyMs: 21000, IncidentIDs: []string{"a", "b"}, Evidence: p,
		Analysis: &analysis.Analysis{
			Summary:         "PID 4127 держит строку.",
			RootCauses:      []analysis.Cause{{Category: "long_transaction", Title: "Незавершённая транзакция", Confidence: 0.9, Evidence: []string{"L1", "M3"}, Explanation: "…"}},
			Recommendations: []analysis.Recommendation{{Action: "Завершить PID 4127", Priority: "now", SQL: "SELECT pg_terminate_backend(4127)", Verify: "ожидающих 0", RequiresApproval: true}},
			Assumptions:     []string{"транзакцию забыло закрыть приложение"},
		}}
	text := FormatAnalysis(r)
	for _, want := range []string{"сигналы: блокировки, замедление SQL", "Предположения, не подтверждённые данными: транзакцию забыло закрыть приложение", "долгая транзакция (уверенность высокая)", "• PID 4127 (shop, idle in transaction, транзакция 34 с) блокирует 7; запрос: UPDATE demo_shop.inventory SET updated_at=now() WHERE product_id=$1",
		"• ожидают блокировку: 0 → 6", "[сейчас, нужно подтверждение]", "DeepSeek-V4-Flash-0731 · 21 с"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "[L1") || strings.Contains(text, "M3,") {
		t.Fatalf("internal ids leaked:\n%s", text)
	}
	if !strings.Contains(FormatAnalysis(analysis.Result{Status: analysis.Pending}), "выполняется") {
		t.Fatal("a running analysis must say so")
	}
	r.Status, r.Reason, r.Model = analysis.Fallback, "timeout", ""
	text = FormatAnalysis(r)
	for _, want := range []string{"Анализ Gonka не получен: нет ответа за отведённое время. Предварительный вывод по правилам hunter, без LLM", "Правила hunter после 21 с ожидания Gonka"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}
