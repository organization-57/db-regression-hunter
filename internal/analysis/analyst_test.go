package analysis

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/evidence"
	"github.com/makeev/db-regression-hunter/internal/llm"
)

type step struct {
	content string
	finish  string
	err     error
	wait    time.Duration
}

type fakeChat struct {
	mu       sync.Mutex
	steps    map[string][]step
	requests []llm.Request
}

func (f *fakeChat) Chat(ctx context.Context, req llm.Request) (llm.Reply, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	queue := f.steps[req.Model]
	if len(queue) == 0 {
		f.mu.Unlock()
		return llm.Reply{Model: req.Model}, &llm.Error{Kind: llm.KindRejected, Msg: "no scripted answer"}
	}
	s := queue[0]
	f.steps[req.Model] = queue[1:]
	f.mu.Unlock()
	if s.wait > 0 {
		select {
		case <-ctx.Done():
			return llm.Reply{Model: req.Model}, &llm.Error{Kind: llm.KindTimeout, Msg: "deadline"}
		case <-time.After(s.wait):
		}
	}
	if s.err != nil {
		return llm.Reply{Model: req.Model}, s.err
	}
	finish := s.finish
	if finish == "" {
		finish = "stop"
	}
	content, _ := llm.SplitThink(s.content)
	return llm.Reply{Model: req.Model, Content: content, FinishReason: finish, PromptTokens: 1200, CompletionTokens: 500}, nil
}

func f(v float64) *float64 { return &v }

func pkg() evidence.Package {
	complete := true
	return evidence.Package{Schema: evidence.Schema,
		Incidents: []evidence.Incident{{ID: "I1", IncidentID: "1-oldest_query_seconds", Findings: []string{"query_age_regression", "lock_contention"}, Status: "open"},
			{ID: "I2", IncidentID: "2-sql", Findings: []string{"sql_execution_regression"}, Status: "open", Statement: "Q1"}},
		Metrics: []evidence.Metric{
			{ID: "M1", Name: "oldest_active_query_age", Unit: "s", Change: evidence.Change{Baseline: f(0.3), Incident: f(21.5)}, Peak: f(31)},
			{ID: "M2", Name: "active_sessions", Unit: "sessions", Change: evidence.Change{Baseline: f(4), Incident: f(11)}},
			{ID: "M3", Name: "lock_waiting_sessions", Unit: "sessions", Change: evidence.Change{Baseline: f(0), Incident: f(6)}, Peak: f(7)},
		},
		Locks: []evidence.Lock{{ID: "L1", BlockingPID: 4127, Root: true, BlockingApplication: "hunter-demo", BlockingState: "idle in transaction",
			TransactionAgeSeconds: 34, BlockedPIDs: []int{4201}, BlockedTotal: 7, WaiterWaitEvents: []string{"Lock:transactionid"}, MaxWaiterQueryAge: 31},
			{ID: "L2", BlockingPID: 4201, BlockedPIDs: []int{4202}, BlockedTotal: 1, WaiterWaitEvents: []string{"Lock:tuple"}}},
		LockGraphComplete: &complete,
		LockGraphCurrent:  true,
		Statements:        []evidence.Statement{{ID: "Q1", QueryID: "-4812771253", MeanExecMS: evidence.Change{Baseline: f(0.6), Incident: f(2480)}}},
		SQLStatistics:     "ready",
	}
}

func answer(mutate func(map[string]any)) string {
	a := map[string]any{
		"summary": "Сессия 4127 в состоянии idle in transaction держит строку, за ней ждут 7 сессий; замедление Q1 — симптом.",
		"root_causes": []any{map[string]any{"category": "long_transaction", "title": "Незавершённая транзакция", "confidence": 0.9,
			"explanation": "L1 блокирует 7 сессий, ожидают Lock до 7 сессий.", "evidence": []string{"L1", "M3", "I1"}}},
		"checks": []any{map[string]any{"step": "Проверить блокирующие PID", "sql": "SELECT pid, pg_blocking_pids(pid) FROM pg_stat_activity", "expect": "PID 4127"}},
		"recommendations": []any{map[string]any{"action": "Завершить транзакцию PID 4127 после согласования", "priority": "now", "risk": "medium",
			"sql": "SELECT pg_terminate_backend(4127)", "verify": "M3 возвращается к 0", "evidence": []string{"L1"}, "requires_approval": false}},
		"assumptions": []string{}, "missing_data": []string{"тексты запросов"},
	}
	if mutate != nil {
		mutate(a)
	}
	data, _ := json.Marshal(a)
	return string(data)
}

func cause(a map[string]any) map[string]any { return a["root_causes"].([]any)[0].(map[string]any) }
func rec(a map[string]any) map[string]any   { return a["recommendations"].([]any)[0].(map[string]any) }

func analyst(c *fakeChat, models ...string) *Analyst {
	return &Analyst{Client: c, Models: models, RepairRounds: 1, Deadline: 2 * time.Second}
}

func outcomes(r Result) string {
	var out []string
	for _, a := range r.Attempts {
		out = append(out, a.Model+":"+a.Outcome)
	}
	return strings.Join(out, ",")
}

func TestValidAnswerIsAcceptedAndDangerousSQLNeedsApproval(t *testing.T) {
	c := &fakeChat{steps: map[string][]step{"a": {{content: "<think>{x}</think>```json\n" + answer(nil) + "\n```"}}}}
	r := analyst(c, "a", "b").Analyze(context.Background(), pkg())
	if r.Status != Done || r.Model != "a" || outcomes(r) != "a:valid" || r.Analysis == nil {
		t.Fatalf("result %+v", r)
	}
	if !r.Analysis.Recommendations[0].RequiresApproval {
		t.Fatal("pg_terminate_backend must require approval even if the model forgot to say so")
	}
	if strings.Join(r.IncidentIDs, ",") != "1-oldest_query_seconds,2-sql" || r.Usage.PromptTokens != 1200 || r.FinishedAt == nil {
		t.Fatalf("result %+v", r)
	}
	if req := c.requests[0]; !req.JSON || req.Messages[0].Role != "system" || !strings.Contains(req.Messages[1].Content, `"regressed_statements"`) {
		t.Fatalf("request %+v", req)
	}
}

func TestStructuralErrorsGetOneRepairRound(t *testing.T) {
	bad := answer(func(a map[string]any) { cause(a)["evidence"] = []string{"L9"} })
	c := &fakeChat{steps: map[string][]step{"a": {{content: bad}, {content: answer(nil)}}}}
	r := analyst(c, "a").Analyze(context.Background(), pkg())
	if r.Status != Done || outcomes(r) != "a:invalid,a:valid" || r.Attempts[0].Excerpt == "" {
		t.Fatalf("result %+v", r)
	}
	if repair := c.requests[1].Messages; len(repair) != 4 || !strings.Contains(repair[3].Content, `unknown evidence id "L9"`) {
		t.Fatalf("repair conversation %+v", repair)
	}
}

func TestOnlyRootBlockersOfACompleteGraphMayBeTerminated(t *testing.T) {
	cases := map[string]string{
		"middle blocker":  "SELECT pg_terminate_backend(4201)",
		"invented pid":    "SELECT pg_cancel_backend(9999)",
		"mass terminate":  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle in transaction'",
		"root plus other": "SELECT pg_terminate_backend(4127); SELECT pg_terminate_backend(4201)",
		"quoted name":     `SELECT "pg_terminate_backend"(999)`,
		"comment inside":  "SELECT pg_terminate_backend/**/(999)",
		"concatenated":    "SELECT query_to_xml('select pg_terminate' || '_backend(999)', true, true, '')",
	}
	for name, sql := range cases {
		unsafe := answer(func(a map[string]any) { rec(a)["sql"] = sql })
		c := &fakeChat{steps: map[string][]step{"a": {{content: unsafe}, {content: answer(nil)}}}}
		r := analyst(c, "a").Analyze(context.Background(), pkg())
		if outcomes(r) != "a:invalid,a:valid" {
			t.Errorf("%s: %s", name, outcomes(r))
		}
	}
	for name, change := range map[string]func(*evidence.Package){
		"incomplete graph": func(p *evidence.Package) { incomplete := false; p.LockGraphComplete = &incomplete },
		"stale graph":      func(p *evidence.Package) { p.LockGraphCurrent = false },
	} {
		p := pkg()
		change(&p)
		c := &fakeChat{steps: map[string][]step{"a": {{content: answer(nil)}, {content: answer(nil)}}}}
		if r := analyst(c, "a").Analyze(context.Background(), p); r.Status != Fallback {
			t.Fatalf("%s must not allow terminating even the root: %s", name, outcomes(r))
		}
	}
	extra := answer(func(a map[string]any) {
		a["recommendations"] = append(a["recommendations"].([]any), map[string]any{"action": "x", "sql": "SELECT pg_terminate_backend(1)", "verify": "M3"})
	})
	c := &fakeChat{steps: map[string][]step{"a": {{content: extra}}}}
	r := analyst(c, "a").Analyze(context.Background(), pkg())
	if r.Status != Done || len(r.Analysis.Recommendations) != 1 || !strings.Contains(strings.Join(r.Warnings, ""), "dropped") {
		t.Fatalf("an unsafe extra recommendation must be dropped without a repair round: %s %+v", outcomes(r), r.Warnings)
	}
}

func TestCategoryMustAgreeWithTheEvidence(t *testing.T) {
	ddl := answer(func(a map[string]any) { cause(a)["category"] = "blocking_ddl" })
	c := &fakeChat{steps: map[string][]step{"a": {{content: ddl}, {content: answer(nil)}}}}
	r := analyst(c, "a").Analyze(context.Background(), pkg())
	if outcomes(r) != "a:invalid,a:valid" || !strings.Contains(strings.Join(r.Attempts[0].Errors, ""), "Lock:relation") {
		t.Fatalf("%s %+v", outcomes(r), r.Attempts)
	}
	p := pkg()
	p.Locks[0].WaiterWaitEvents = []string{"Lock:relation"}
	c = &fakeChat{steps: map[string][]step{"a": {{content: ddl}}}}
	if r := analyst(c, "a").Analyze(context.Background(), p); r.Status != Done || len(r.Attempts) != 1 {
		t.Fatalf("waiters on Lock:relation support blocking_ddl: %+v", r.Attempts)
	}
	slow := answer(func(a map[string]any) { cause(a)["evidence"] = []string{"M1"} })
	c = &fakeChat{steps: map[string][]step{"a": {{content: slow}, {content: slow}}}}
	if r := analyst(c, "a").Analyze(context.Background(), pkg()); r.Status != Fallback || r.Reason != "invalid_answer" {
		t.Fatalf("long_transaction without a cited blocker must not pass: %s %s", outcomes(r), r.Reason)
	}
	dead := answer(func(a map[string]any) { cause(a)["category"] = "deadlock" })
	c = &fakeChat{steps: map[string][]step{"a": {{content: dead}, {content: dead}}}}
	if r := analyst(c, "a").Analyze(context.Background(), pkg()); r.Status != Fallback {
		t.Fatalf("deadlock without a deadlock incident must not pass: %s", outcomes(r))
	}
}

func TestForeignScriptNeedsARepairRound(t *testing.T) {
	mixed := answer(func(a map[string]any) { a["assumptions"] = []string{"разовая задача (批处理)"} })
	c := &fakeChat{steps: map[string][]step{"a": {{content: mixed}, {content: answer(nil)}}}}
	r := analyst(c, "a").Analyze(context.Background(), pkg())
	if outcomes(r) != "a:invalid,a:valid" || !strings.Contains(strings.Join(r.Attempts[0].Errors, ""), "Russian") {
		t.Fatalf("%s %+v", outcomes(r), r.Attempts)
	}
}

func TestCosmeticProblemsAreFixedWithoutARepairRound(t *testing.T) {
	sloppy := answer(func(a map[string]any) {
		a["checks"] = append(a["checks"].([]any), map[string]any{"step": "Сбросить статистику", "sql": "SELECT pg_stat_reset()", "expect": "-"})
		r := rec(a)
		r["priority"], r["risk"], r["evidence"] = "", "", []string{"Z7"}
	})
	c := &fakeChat{steps: map[string][]step{"a": {{content: sloppy}}}}
	r := analyst(c, "a").Analyze(context.Background(), pkg())
	if r.Status != Done || len(c.requests) != 1 {
		t.Fatalf("cosmetic problems must not cost a repair round: %+v", r)
	}
	a := r.Analysis
	if len(a.Checks) != 1 || len(a.Recommendations) != 2 || !a.Recommendations[1].RequiresApproval {
		t.Fatalf("not normalized: %+v", a)
	}
	if a.Recommendations[0].Priority != "next" || a.Recommendations[0].Risk != "medium" || len(a.Recommendations[0].Evidence) != 0 {
		t.Fatalf("labels not defaulted: %+v", a.Recommendations[0])
	}
}

func TestFailoverHedgingWavesAndFailures(t *testing.T) {
	c := &fakeChat{steps: map[string][]step{
		"a": {{err: &llm.Error{Kind: llm.KindTimeout, Msg: "no answer"}}},
		"b": {{content: "not json", finish: "length"}, {content: answer(nil)}},
	}}
	if r := analyst(c, "a", "b").Analyze(context.Background(), pkg()); r.Model != "b" || outcomes(r) != "a:timeout,b:invalid,b:valid" {
		t.Fatalf("failover: %s", outcomes(r))
	}
	c = &fakeChat{steps: map[string][]step{"slow": {{wait: time.Minute, content: answer(nil)}}, "fast": {{wait: 20 * time.Millisecond, content: answer(nil)}}}}
	a := analyst(c, "slow", "fast")
	a.HedgeAfter = 30 * time.Millisecond
	start := time.Now()
	if r := a.Analyze(context.Background(), pkg()); r.Model != "fast" || time.Since(start) > time.Second || !strings.Contains(outcomes(r), "slow:cancelled") {
		t.Fatalf("hedging: %s after %v", outcomes(r), time.Since(start))
	}
	timeout := &llm.Error{Kind: llm.KindTimeout, Msg: "no answer"}
	c = &fakeChat{steps: map[string][]step{"a": {{err: timeout}, {content: answer(nil)}}}}
	a = analyst(c, "a")
	a.Waves = 2
	if r := a.Analyze(context.Background(), pkg()); r.Status != Done || r.Attempts[len(r.Attempts)-1].Wave != 2 {
		t.Fatalf("second wave: %+v", r.Attempts)
	}
	c = &fakeChat{steps: map[string][]step{"a": {{wait: time.Minute}}}}
	a = analyst(c, "a")
	a.Deadline = 50 * time.Millisecond
	r := a.Analyze(context.Background(), pkg())
	if r.Status != Fallback || r.Reason != "timeout" || !strings.Contains(r.Error, "no valid answer within 50ms") {
		t.Fatalf("deadline: %+v", r)
	}
	if r.Schema != ResultSchema || r.Analysis == nil || r.Analysis.RootCauses[0].Category != "long_transaction" || r.Model != "" || len(r.Warnings) != 0 {
		t.Fatalf("without an answer the rules explain the same evidence: %+v", r.Analysis)
	}
	if r := analyst(&fakeChat{}).Analyze(context.Background(), pkg()); r.Status != Fallback || r.Reason != "unavailable" || r.Error != "no model was called" {
		t.Fatalf("no models: %+v", r)
	}
}
