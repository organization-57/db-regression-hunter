package main

import (
	"html"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/makeev/db-regression-hunter/internal/analysis"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/telegram"
)

func TestAnalysisAnnotationPreservesHTMLLink(t *testing.T) {
	l := &llmLayer{}
	l.results.Put(analysis.Result{ID: "a", IncidentIDs: []string{"i"}, Status: analysis.Done,
		Analysis: &analysis.Analysis{Summary: strings.Repeat("SELECT a < 3 & b > 1; 🟢", 200)}})
	i := detector.Incident{ID: "i", StartedAt: time.Now(), Findings: []detector.Finding{detector.Finding(strings.Repeat("x", 4000))}}
	base := telegram.New("", "", "http://localhost:3000/d/hunter").IncidentSummary(i)
	text := l.withAnalysis(base, "i")
	if !strings.HasPrefix(text, base+"\n\n") || !strings.Contains(text, "Ссылка на окно в Grafana</a>") {
		t.Fatal("annotation damaged incident or link", text)
	}
	if strings.Contains(text, "SELECT a < 3") || !strings.Contains(text, "SELECT a &lt; 3 &amp; b &gt; 1") {
		t.Fatal("analysis was not escaped", text)
	}
	visible := regexp.MustCompile(`<a href="[^"]*">([^<]*)</a>`).ReplaceAllString(text, "$1")
	if len(utf16.Encode([]rune(html.UnescapeString(visible)))) > 4000 {
		t.Fatal("message exceeded budget")
	}
}
