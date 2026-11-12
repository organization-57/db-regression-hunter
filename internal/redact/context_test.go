package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestQueryAnonymization(t *testing.T) {
	a := New()
	raw := `/* customer-secret /* nested-secret */ */ SELECT c."PrivateEmail", count(*) FROM "PrivateSchema"."PrivateCustomers" c WHERE c."PrivateEmail" = 'literal-secret''suffix' AND c."SecretAmount" > 987654 AND c."SecretNote" = $tag$dollar-secret$tag$ AND c."SecretID"=$1 -- comment-secret`
	safe, err := a.SQL(raw)
	if err != nil {
		t.Fatal(err)
	}
	plan := a.Plan(map[string]any{"Node Type": "Seq Scan", "Schema": "PrivateSchema", "Relation Name": "PrivateCustomers", "Alias": "c", "Filter": `c."PrivateEmail" = 'plan-secret'::text`, "Plan Rows": 42.0, "Provider Secret": "provider-secret", "Output": []any{`c."PrivateEmail"`}})
	data, _ := json.Marshal(plan)
	for _, secret := range []string{"Private", "Secret", "secret", "987654"} {
		if strings.Contains(safe+string(data), secret) {
			t.Fatalf("leaked %q: %s %s", secret, safe, data)
		}
	}
	if !strings.Contains(safe, `"`+a.Name("PrivateCustomers")+`"`) || plan["Relation Name"] != a.Name("PrivateCustomers") || !strings.Contains(plan["Filter"].(string), `"`+a.Name("PrivateEmail")+`"`) {
		t.Fatal("names do not match across SQL and plan")
	}
	if plan["Plan Rows"] != 42.0 || !strings.Contains(safe, "$1") || !strings.Contains(plan["Filter"].(string), ":: text") {
		t.Fatal("lost structural information", safe, plan)
	}
	for _, input := range []string{`select 'unterminated`, `select /* missing`, `select 1; select 2`, `select E'escaped\'secret'`, `select U&"escaped\0061"`, "select \x00secret", `select $tag$unclosed`} {
		if result, err := a.SQL(input); err == nil || result != "" {
			t.Fatalf("must fail closed: %q", input)
		}
	}
	typ, err := a.tokens("numeric(12,2)", false)
	if err != nil || !strings.Contains(typ, "12") || !strings.Contains(typ, "2") {
		t.Fatal("type precision lost", typ, err)
	}
}
