package telegram

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/detector"
)

func TestIncidentDeliveryHTML(t *testing.T) {
	at := time.Date(2026, 11, 11, 22, 23, 19, 0, time.UTC)
	for _, status := range []string{detector.Open, detector.Recovering, detector.Resolved} {
		i := detector.Incident{ID: "<incident>&", Status: status, StartedAt: at, DetectedAt: at.Add(time.Minute), ResolvedAt: &at,
			SQLRegression: &detector.SQLRegression{LastObservedAt: at}}
		b := New("test", "123", "http://localhost:3000/d/hunter?orgId=2&var-db=demo")
		b.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var payload struct {
				Text      string `json:"text"`
				ParseMode string `json:"parse_mode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload.ParseMode != "HTML" || payload.Text != b.IncidentSummary(i) {
				t.Fatal(payload)
			}
			indicator := "🔴"
			if status == detector.Resolved {
				indicator = "🟢"
			}
			for _, want := range []string{indicator + " Инцидент &lt;incident&gt;&amp;", "http://127.0.0.1:3000/", "&amp;orgId=2", ">Ссылка на окно в Grafana</a>"} {
				if !strings.Contains(payload.Text, want) {
					t.Fatalf("missing %q: %s", want, payload.Text)
				}
			}
			if strings.Count(payload.Text, "12.11.2026 01:23:19 МСК") != 3 {
				t.Fatal("inconsistent timestamps", payload.Text)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
		})
		if err := b.Notify(context.Background(), i); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSendPreservesLiteralText(t *testing.T) {
	b := New("test", "123", "")
	text := "SELECT * FROM t WHERE a < 3 AND b > 1; <a href=\"bad\"> &"
	b.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["text"] != html.EscapeString(text) || payload["parse_mode"] != "HTML" {
			t.Fatal(payload)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})
	if err := b.Send(context.Background(), text); err != nil {
		t.Fatal(err)
	}
}

func TestFormatIncidentReadableFindings(t *testing.T) {
	i := detector.Incident{
		Findings: []detector.Finding{
			detector.FindingQueryAgeRegression, detector.FindingLockWait,
			detector.FindingLockContention, detector.FindingIdleInTransaction,
			detector.FindingActiveSessionsSurge, detector.FindingTempFileGrowth,
			detector.FindingDeadlock, detector.FindingSQLExecutionRegression,
			"future_finding",
		},
		Trigger: detector.Trigger{Metric: "test", Observed: 4, Baseline: 1, Threshold: 3},
		Peak:    5,
	}
	text := FormatIncident(i)
	for _, want := range []string{
		"Факты: долгие активные запросы, ожидание блокировок, найдены корневые блокировщики, простой с открытой транзакцией, всплеск активных сессий, рост записи временных файлов, deadlock, замедление SQL, future_finding",
		"test: 4.00; baseline: 1.00; threshold: 3.00; peak: 5.00",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
	if i.Findings[0] != detector.FindingQueryAgeRegression {
		t.Fatal("presentation changed machine-readable findings")
	}
}
