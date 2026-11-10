package telegram

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/detector"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNotifyExplainsBlockingAndRecovery(t *testing.T) {
	bot := New("test-token", "123", "http://grafana.local")
	var messages []string
	bot.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var payload struct {
			ChatID string `json:"chat_id"`
			Text   string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.ChatID != "123" {
			t.Fatal("wrong chat")
		}
		messages = append(messages, payload.Text)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":{}}`))}, nil
	})
	at := time.Now()
	i := detector.Incident{ID: "episode", StartedAt: at, Status: detector.Active,
		Evidence: []string{"PID 10 ждёт PID 20", "PID 20 ждёт PID 30"}}
	if err := bot.Notify(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	i.Status = detector.Resolved
	i.RecoveredAt = &at
	if err := bot.Notify(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || !strings.Contains(messages[0], "active") || !strings.Contains(messages[0], "PID 20 ждёт PID 30") || !strings.Contains(messages[1], "resolved") || !strings.Contains(messages[1], "Восстановление симптомов БД подтверждено") {
		t.Fatalf("missing lifecycle report: %v", messages)
	}
}
