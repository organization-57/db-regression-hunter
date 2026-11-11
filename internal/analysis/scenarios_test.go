package analysis

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/makeev/db-regression-hunter/internal/config"
	"github.com/makeev/db-regression-hunter/internal/evidence"
	"github.com/makeev/db-regression-hunter/internal/llm"
)

type scenario struct {
	Scenario string           `json:"scenario"`
	Expect   []string         `json:"expect"`
	Evidence evidence.Package `json:"evidence"`
}

func strict(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		t.Fatalf("%s does not match the contract: %v", path, err)
	}
}

func recorded(t *testing.T) []scenario {
	t.Helper()
	paths, _ := filepath.Glob("testdata/scenarios/*.json")
	if len(paths) == 0 {
		t.Fatal("no recorded scenarios")
	}
	var out []scenario
	for _, path := range paths {
		var s scenario
		strict(t, path, &s)
		if s.Evidence.Schema != evidence.Schema || len(s.Expect) == 0 {
			t.Fatalf("%s: schema %q, expect %v", path, s.Evidence.Schema, s.Expect)
		}
		out = append(out, s)
	}
	return out
}

func TestRulesOnRecordedScenarios(t *testing.T) {
	for _, s := range recorded(t) {
		a := Rules(s.Evidence)
		if v := check(&a, s.Evidence); len(v.errors) > 0 {
			t.Errorf("%s: %v", s.Scenario, v.errors)
		}
		got := a.RootCauses[0].Category
		t.Logf("%-14s rules: %-22s expected %v", s.Scenario, got, s.Expect)
		if !contains(s.Expect, got) {
			t.Errorf("%s: rules say %s, expected one of %v", s.Scenario, got, s.Expect)
		}
	}
}

func TestContractAnswerExample(t *testing.T) {
	var s scenario
	strict(t, "testdata/scenarios/row_lock.json", &s)
	content, err := os.ReadFile("testdata/contract/answer.json")
	if err != nil {
		t.Fatal(err)
	}
	var shape Analysis
	strict(t, "testdata/contract/answer.json", &shape)
	a, warnings, problems := judge(llm.Reply{Content: string(content), FinishReason: "stop"}, s.Evidence)
	if len(problems) > 0 || len(warnings) > 0 || a.RootCauses[0].Category != "long_transaction" || !a.Recommendations[0].RequiresApproval {
		t.Fatalf("the documented answer must pass validation unchanged: %v %v %+v", problems, warnings, a)
	}
}

func TestModelOnRecordedScenarios(t *testing.T) {
	if os.Getenv("HUNTER_LIVE_LLM") != "1" {
		t.Skip("set HUNTER_LIVE_LLM=1 and GONKA_API_KEY to call Gonka")
	}
	cfg, err := config.LoadLLM()
	if err != nil || !cfg.Enabled() {
		t.Skip("GONKA_API_KEY is not set")
	}
	a := NewAnalyst(cfg)
	for _, s := range recorded(t) {
		r := a.Analyze(context.Background(), s.Evidence)
		category := ""
		if r.Analysis != nil {
			category = r.Analysis.RootCauses[0].Category
		}
		t.Logf("%-14s %-8s %-36s %6.1f s  %-22s attempts %d", s.Scenario, r.Status, r.Model, float64(r.LatencyMs)/1000, category, len(r.Attempts))
		if r.Status != Done || !contains(s.Expect, category) {
			t.Errorf("%s: %s %s, expected one of %v (%s)", s.Scenario, r.Status, category, s.Expect, r.Error)
		}
	}
}
