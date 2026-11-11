package config

import "testing"

func TestLLMIsOptionalAndValidatedOnlyWhenEnabled(t *testing.T) {
	t.Setenv("GONKA_API_KEY", "")
	t.Setenv("ANALYSIS_DELAY", "soon")
	if l, err := LoadLLM(); err != nil || l.Enabled() {
		t.Fatalf("without a key the LLM settings must not stop the service: %+v %v", l, err)
	}
	t.Setenv("GONKA_API_KEY", "k")
	if _, err := LoadLLM(); err == nil {
		t.Fatal("invalid delay accepted with a key")
	}
	t.Setenv("ANALYSIS_DELAY", "")
	if l, err := LoadLLM(); err != nil || len(l.Models) != 2 || l.Delay.Seconds() != 25 || !l.SQLText {
		t.Fatalf("%+v %v", l, err)
	}
	t.Setenv("ANALYSIS_SQL_TEXT", "maybe")
	if _, err := LoadLLM(); err == nil {
		t.Fatal("invalid ANALYSIS_SQL_TEXT accepted")
	}
	t.Setenv("ANALYSIS_SQL_TEXT", "false")
	if l, err := LoadLLM(); err != nil || l.SQLText {
		t.Fatalf("texts must be switchable off: %+v %v", l, err)
	}
}
