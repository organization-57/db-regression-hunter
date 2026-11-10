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

func TestIncidentCommand(t *testing.T) {
	i := detector.Incident{ID: "1794321188121986000", Status: detector.Open, StartedAt: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC), DetectedAt: time.Date(2026, 11, 10, 12, 0, 20, 0, time.UTC), Finding: "lock_contention"}
	for _, tc := range []struct {
		name, command, want string
		lookupCalls         int
		legacy              bool
	}{
		{name: "found", command: "/incident " + i.ID, lookupCalls: 1},
		{name: "mention and whitespace", command: " /incident@HunterBot  " + i.ID + "  ", lookupCalls: 1},
		{name: "not found", command: "/incident missing-id", want: "Расследование не найдено", lookupCalls: 1},
		{name: "missing argument", command: "/incident", want: "Использование: /incident <ID>"},
		{name: "extra argument", command: "/incident 123 456", want: "Использование: /incident <ID>"},
		{name: "help", command: "/help", want: "/incident <ID>"},
		{name: "start", command: "/start", want: "/incident <ID>"},
		{name: "latest", command: "/incidents", want: "latest"},
		{name: "status", command: "/status", want: "status"},
		{name: "legacy run", command: "/incident 123", want: "Поиск расследований по ID недоступен", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			b := New("test-token", "513", "https://grafana.test/d/hunter")
			lookupCalls, sendCalls, pollCalls := 0, 0, 0
			lookup := func(id string) (detector.Incident, bool) { lookupCalls++; return i, id == i.ID }
			b.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body := `{"ok":true,"result":{}}`
				switch r.URL.Path {
				case "/bottest-token/getUpdates":
					pollCalls++
					if pollCalls > 1 {
						t.Fatal("command was not answered")
					}
					// The unauthorized lookup must be ignored before invoking the callback.
					updates := []any{}
					for n, chat := range []int{999, 513} {
						updates = append(updates, map[string]any{"update_id": n + 1, "message": map[string]any{"text": tc.command, "chat": map[string]any{"id": chat}}})
					}
					data, err := json.Marshal(map[string]any{"ok": true, "result": updates})
					if err != nil {
						t.Fatal(err)
					}
					body = string(data)
				case "/bottest-token/sendMessage":
					sendCalls++
					var payload struct {
						ChatID string `json:"chat_id"`
						Text   string `json:"text"`
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					if payload.ChatID != "513" {
						t.Fatal("wrong recipient", payload.ChatID)
					}
					if tc.want == "" {
						if payload.Text != b.IncidentSummary(i) {
							t.Fatal("lookup must reuse incident formatter", payload.Text)
						}
					} else if !strings.Contains(payload.Text, tc.want) {
						t.Fatalf("expected %q in %q", tc.want, payload.Text)
					}
					cancel()
				default:
					t.Fatal("unexpected request", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			if tc.legacy {
				b.Run(ctx, func() string { return "status" }, func() string { return "latest" })
			} else {
				b.RunWithIncidentLookup(ctx, func() string { return "status" }, func() string { return "latest" }, lookup)
			}
			if lookupCalls != tc.lookupCalls || sendCalls != 1 {
				t.Fatal("unexpected callback or send count", lookupCalls, sendCalls)
			}
		})
	}
}
