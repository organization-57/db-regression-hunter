package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/makeev/db-regression-hunter/internal/analysis"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/evidence"
)

func visible(s string) string {
	return html.UnescapeString(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(s, ""))
}

func lockResult() analysis.Result {
	base, now := 0.0, 6.0
	p := &evidence.Package{
		Incidents: []evidence.Incident{{ID: "I1", Findings: []string{"lock_contention", "idle_in_transaction"}}},
		Metrics:   []evidence.Metric{{ID: "M3", Name: "lock_waiting_sessions", Change: evidence.Change{Baseline: &base, Incident: &now}}},
		Locks: []evidence.Lock{{ID: "L1", BlockingPID: 4127, BlockingApplication: "shop", BlockingState: "idle in transaction", TransactionAgeSeconds: 34, BlockedTotal: 7,
			BlockingQuery: "UPDATE demo_shop.inventory SET updated_at=now() WHERE product_id=$1"}},
	}
	return analysis.Result{Status: analysis.Done, Model: "deepseek-ai/DeepSeek-V4-Flash-0731", LatencyMs: 21000, IncidentIDs: []string{"a", "b"}, Evidence: p,
		Analysis: &analysis.Analysis{
			RootCauses: []analysis.Cause{
				{Category: "long_transaction", Title: "PID 4127 не закрывает транзакцию и держит строку", Confidence: 0.9, Evidence: []string{"L1", "M3", "I1"},
					Explanation: "Транзакция простаивает 34 с, ожидающие ждут Lock:transactionid, а не всю таблицу."},
				{Category: "lock_contention", Title: "Конкуренция за одну строку", Confidence: 0.3, Evidence: []string{"M3"}, Explanation: "Много обновлений одной строки."},
			},
			Recommendations: []analysis.Recommendation{
				{Action: "Завершить PID 4127", Priority: "now", SQL: "SELECT pg_terminate_backend(4127)", Verify: "ожидающих 0", RequiresApproval: true},
				{Action: "Включить idle_in_transaction_session_timeout", Priority: "next", Verify: "транзакции закрываются сами"},
				{Action: "Найти в приложении незакрытую транзакцию", Priority: "later", Verify: "нет повторов"},
			},
			Checks:      []analysis.Check{{Step: "Посмотреть транзакцию PID 4127", SQL: "SELECT state FROM pg_stat_activity WHERE pid = 4127 AND 1 < 2"}},
			Assumptions: []string{"транзакцию забыло закрыть приложение"},
			MissingData: []string{"журнал приложения"},
		}}
}

func TestAnalysisCardSaysEachThingOnceAndFoldsTheRest(t *testing.T) {
	text := FormatAnalysis(lockResult())
	card, details, folded := strings.Cut(text, "<blockquote expandable>")
	if !folded || !strings.HasSuffix(details, "</blockquote>") {
		t.Fatalf("details must be folded:\n%s", text)
	}
	for _, want := range []string{"<b>Причина:</b> PID 4127 не закрывает транзакцию и держит строку · уверенность высокая",
		"<b>Почему:</b> Транзакция простаивает 34 с", "<b>Что сделать</b>\n1. Завершить PID 4127 · нужно подтверждение\n<code>SELECT pg_terminate_backend(4127)</code>",
		"2. Включить idle_in_transaction_session_timeout"} {
		if !strings.Contains(card, want) {
			t.Errorf("card misses %q:\n%s", want, card)
		}
	}
	for _, unwanted := range []string{"Gonka", "Найти в приложении", "UPDATE demo_shop", "ожидают блокировку", "Конкуренция", "M3", "L1"} {
		if strings.Contains(card, unwanted) {
			t.Errorf("card must not show %q:\n%s", unwanted, card)
		}
	}
	for _, want := range []string{"<b>Данные</b>\n• PID 4127 (shop, простой с открытой транзакцией, транзакция 34 с) блокирует 7; запрос: UPDATE demo_shop.inventory",
		"• ожидают блокировку: 0 → 6", "<b>Ещё действия</b>\n3. Найти в приложении незакрытую транзакцию", "<code>SELECT state FROM pg_stat_activity WHERE pid = 4127 AND 1 &lt; 2</code>",
		"<b>Другие версии</b>\n• Конкуренция за одну строку · уверенность низкая", "• транзакцию забыло закрыть приложение", "• журнал приложения",
		"Категория: долгая транзакция · модель DeepSeek-V4-Flash-0731"} {
		if !strings.Contains(details, want) {
			t.Errorf("details miss %q:\n%s", want, details)
		}
	}
	if n := len([]rune(visible(card))); n > 450 {
		t.Errorf("card is %d characters:\n%s", n, card)
	}
}

func TestAnalysisGroupsIdenticalSessions(t *testing.T) {
	p := &evidence.Package{}
	var ids []string
	for n, pid := range []int{94068, 94159, 94067, 94073, 94424} {
		id := fmt.Sprintf("S%d", n+1)
		ids = append(ids, id)
		p.Sessions = append(p.Sessions, evidence.Session{ID: id, PID: pid, Application: "hunter-demo", State: "active", WaitEvent: "Timeout:PgSleep", QueryAgeSeconds: 52.6})
	}
	p.Sessions = append(p.Sessions, evidence.Session{ID: "S6", PID: 7, Application: "report", State: "active", QueryAgeSeconds: 3})
	ids = append(ids, "S6")
	r := analysis.Result{Status: analysis.Done, Evidence: p, Analysis: &analysis.Analysis{
		RootCauses:      []analysis.Cause{{Category: "slow_query", Title: "Приложение держит соединения в pg_sleep", Confidence: 0.9, Evidence: ids, Explanation: "Блокировок нет."}},
		Recommendations: []analysis.Recommendation{{Action: "Убрать pg_sleep из приложения"}}}}
	text := FormatAnalysis(r)
	for _, want := range []string{"• 5 сессий hunter-demo, Timeout:PgSleep, до 52.6 с: PID 94068, 94159, 94067, 94073, 94424", "• PID 7 (report, выполняет запрос) выполняется 3 с"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "Timeout:PgSleep") != 1 {
		t.Errorf("identical sessions must be one line:\n%s", text)
	}
}

func TestAnalysisFitsTelegramAndEscapesModelText(t *testing.T) {
	r := lockResult()
	hostile := strings.Repeat("a < 3 & b > 1 🟢 ", 400)
	a := r.Analysis
	a.RootCauses[0].Title, a.RootCauses[0].Explanation = hostile, hostile
	for n := range a.Recommendations {
		a.Recommendations[n].Action, a.Recommendations[n].SQL = hostile, hostile
	}
	a.Assumptions, a.MissingData = []string{hostile, hostile}, []string{hostile, hostile}
	for name, c := range map[string]struct {
		text   string
		budget int
	}{"message": {FormatAnalysis(r), messageBudget}, "incident card": {AnalysisCard(r, 900), 900}} {
		if strings.Contains(c.text, "a < 3") || !strings.Contains(c.text, "a &lt; 3 &amp; b &gt; 1") {
			t.Errorf("%s: model text was not escaped", name)
		}
		if n := units(visible(c.text)); n > c.budget {
			t.Errorf("%s: %d units exceed %d", name, n, c.budget)
		}
		if strings.Count(c.text, "<b>") != strings.Count(c.text, "</b>") || strings.Count(c.text, "<code>") != strings.Count(c.text, "</code>") {
			t.Errorf("%s: unbalanced markup:\n%s", name, c.text)
		}
	}
	if strings.Contains(AnalysisCard(r, 900), "blockquote") {
		t.Error("the incident card must not carry the folded details")
	}
}

func TestAnalysisSaysWhenItIsNotFromTheModel(t *testing.T) {
	r := lockResult()
	r.Status, r.Reason, r.Model = analysis.Fallback, "timeout", ""
	text := FormatAnalysis(r)
	for _, want := range []string{"<b>Предварительно, без LLM:</b> модель не ответила за отведённое время\n<b>Причина:</b>", "правила hunter без LLM"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, text)
		}
	}
	if FormatAnalysis(analysis.Result{Status: analysis.Pending}) != "Анализ причины выполняется." {
		t.Error("a running analysis must say so")
	}
}

func TestAnalysisRepliesToTheIncidentAlert(t *testing.T) {
	b := New("test", "513", "")
	var replies []any
	b.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var payload map[string]any
		if strings.HasSuffix(r.URL.Path, "sendMessage") {
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			replies = append(replies, payload["reply_parameters"])
		}
		id := 100 + len(replies)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, id)))}, nil
	})
	ctx := context.Background()
	for _, status := range []string{detector.Open, detector.Resolved} {
		if err := b.Notify(ctx, detector.Incident{ID: "b", Status: status}); err != nil {
			t.Fatal(err)
		}
	}
	r := lockResult()
	r.Evidence = nil
	if err := b.NotifyAnalysis(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.IncidentIDs = []string{"unknown"}
	if err := b.NotifyAnalysis(ctx, r); err != nil {
		t.Fatal(err)
	}
	if replies[0] != nil || replies[1] != nil || replies[3] != nil {
		t.Fatalf("only the analysis of a known incident is a reply: %v", replies)
	}
	if got, ok := replies[2].(map[string]any); !ok || got["message_id"] != float64(101) || got["allow_sending_without_reply"] != true {
		t.Fatalf("analysis must reply to the first alert of its incident: %v", replies[2])
	}
}
