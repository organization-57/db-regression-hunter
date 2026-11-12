package analysis

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/makeev/db-regression-hunter/internal/evidence"
)

func TestOnlyAnonymousEvidenceReachesModelAndNamesReturnLocally(t *testing.T) {
	p := pkg()
	p.Tables = []evidence.Table{{ID: "T1", NamesFrom: "I1", Schema: "SecretBilling", Name: "PrivateLedger", Columns: []evidence.Column{{Name: "SecretEmail", Type: "text"}}, Constraints: []string{`CHECK ("SecretEmail" <> 'constraint-secret')`}}}
	p.Locks[0].BlockingQuery = `SELECT "SecretEmail" FROM "SecretBilling"."PrivateLedger" WHERE "SecretEmail"='literal-secret'`
	p.Locks[0].BlockingApplication = "business-secret-app"
	safe, _, err := p.ForLLM()
	if err != nil {
		t.Fatal(err)
	}
	name := safe.Tables[0].Name
	c := &fakeChat{steps: map[string][]step{"a": {{content: `{"summary":"Недостаточный ответ"}`}, {content: answer(func(m map[string]any) { m["summary"] = "Проблема таблицы " + name })}}}}
	r := analyst(c, "a").Analyze(context.Background(), p)
	if r.Status != Done || !strings.Contains(r.Analysis.Summary, "PrivateLedger") || strings.Contains(r.Analysis.Summary, name) {
		t.Fatal("names not restored", r)
	}
	if r.Evidence.Tables[0].Name != "PrivateLedger" || !strings.Contains(r.Evidence.Locks[0].BlockingQuery, "literal-secret") {
		t.Fatal("stored/Telegram evidence was anonymized")
	}
	if len(c.requests) != 2 {
		t.Fatal("unexpected model calls", len(c.requests))
	}
	for _, req := range c.requests {
		for _, m := range req.Messages {
			for _, secret := range []string{"SecretBilling", "PrivateLedger", "SecretEmail", "business-secret", "constraint-secret", "literal-secret"} {
				if strings.Contains(m.Content, secret) {
					t.Fatalf("model request leaked %q", secret)
				}
			}
		}
	}
}

func TestInvalidEvidenceNeverFallsBackToRawModelRequest(t *testing.T) {
	p := pkg()
	bad := math.NaN()
	p.Metrics[0].Baseline = &bad
	c := &fakeChat{}
	r := analyst(c, "a").Analyze(context.Background(), p)
	if r.Status != Fallback || r.Reason != "invalid_evidence" || len(c.requests) != 0 {
		t.Fatal("invalid evidence reached model", r)
	}
}
