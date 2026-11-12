package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/makeev/db-regression-hunter/internal/detector"
)

const rememberedAlerts = 256

type Bot struct {
	token, chatID, grafanaURL string
	client                    *http.Client
	Annotate                  func(text, incidentID string) string
	mu                        sync.Mutex
	alerts                    map[string]int64
	alertOrder                []string
}

func New(token, chatID, grafanaURL string) *Bot {
	return &Bot{token: token, chatID: chatID, grafanaURL: grafanaURL, client: &http.Client{Timeout: 40 * time.Second}}
}

func (b *Bot) call(ctx context.Context, method string, payload any, result any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+b.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build Telegram request")
	}
	req.Header.Set("Content-Type", "application/json")
	return b.do(req, result)
}

func (b *Bot) do(req *http.Request, result any) error {
	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("Telegram transport failed")
	} // URL contains the token: never log transport errors.
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Telegram HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&envelope); err != nil {
		return fmt.Errorf("invalid Telegram response")
	}
	if !envelope.OK {
		return fmt.Errorf("Telegram rejected request")
	}
	if result != nil && len(envelope.Result) > 0 {
		return json.Unmarshal(envelope.Result, result)
	}
	return nil
}

func (b *Bot) Send(ctx context.Context, message string) error {
	return b.sendHTML(ctx, html.EscapeString(message))
}

func (b *Bot) sendHTML(ctx context.Context, message string) error {
	_, err := b.post(ctx, message, 0)
	return err
}

func (b *Bot) post(ctx context.Context, message string, replyTo int64) (int64, error) {
	payload := map[string]any{"chat_id": b.chatID, "text": message, "parse_mode": "HTML", "link_preview_options": map[string]bool{"is_disabled": true}}
	if replyTo != 0 {
		payload["reply_parameters"] = map[string]any{"message_id": replyTo, "allow_sending_without_reply": true}
	}
	var sent struct {
		MessageID int64 `json:"message_id"`
	}
	err := b.call(ctx, "sendMessage", payload, &sent)
	return sent.MessageID, err
}

func (b *Bot) remember(incidentID string, messageID int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if messageID == 0 || b.alerts[incidentID] != 0 {
		return
	}
	if b.alerts == nil {
		b.alerts = map[string]int64{}
	}
	if len(b.alertOrder) == rememberedAlerts {
		delete(b.alerts, b.alertOrder[0])
		b.alertOrder = b.alertOrder[1:]
	}
	b.alerts[incidentID] = messageID
	b.alertOrder = append(b.alertOrder, incidentID)
}

func (b *Bot) alertFor(incidentIDs []string) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range incidentIDs {
		if m := b.alerts[id]; m != 0 {
			return m
		}
	}
	return 0
}

func (b *Bot) Notify(ctx context.Context, i detector.Incident) error {
	messageID, err := b.post(ctx, b.IncidentSummary(i), 0)
	if err != nil {
		return err
	}
	b.remember(i.ID, messageID)
	if len(i.Queries) > 0 || len(i.Tables) > 0 {
		return b.SendDocument(ctx, "incident-"+i.ID+".json", i)
	}
	return nil
}

func (b *Bot) Run(ctx context.Context, status func() string, latest func() string) {
	b.RunWithIncidentLookup(ctx, status, latest, nil)
}

// RunWithIncidentLookup adds ID lookup while preserving the original Run API.
// latest and Annotate return Telegram HTML; status returns plain text.
func (b *Bot) RunWithIncidentLookup(ctx context.Context, status func() string, latest func() string, lookup func(string) (detector.Incident, bool)) {
	var offset int64
	for ctx.Err() == nil {
		var updates []struct {
			UpdateID int64 `json:"update_id"`
			Message  *struct {
				Text string `json:"text"`
				Chat struct {
					ID int64 `json:"id"`
				} `json:"chat"`
			} `json:"message"`
		}
		if err := b.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": 25, "allowed_updates": []string{"message"}}, &updates); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("Telegram polling failed", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		for _, u := range updates {
			offset = u.UpdateID + 1
			if u.Message == nil || fmt.Sprint(u.Message.Chat.ID) != b.chatID {
				continue
			}
			parts := strings.Fields(u.Message.Text)
			if len(parts) == 0 {
				continue
			}
			command := strings.SplitN(parts[0], "@", 2)[0]
			var answer string
			isHTML := false
			switch command {
			case "/status":
				answer = status()
			case "/incidents":
				answer = latest()
				isHTML = true
			case "/incident":
				if len(parts) != 2 {
					answer = "Использование: /incident <ID>"
				} else if lookup == nil {
					answer = "Поиск расследований по ID недоступен"
				} else if incident, ok := lookup(parts[1]); ok {
					answer = b.IncidentSummary(incident)
					isHTML = true
					if b.Annotate != nil {
						answer = b.Annotate(answer, incident.ID)
					}
				} else {
					answer = "Расследование не найдено. Хранятся только последние 100 расследований; после перезапуска они теряются."
				}
			case "/start", "/help":
				answer = "/status — состояние PostgreSQL\n/incidents — последнее расследование\n/incident <ID> — расследование по ID"
			default:
				continue
			}
			if !isHTML {
				answer = html.EscapeString(answer)
			}
			if err := b.sendHTML(ctx, answer); err != nil {
				slog.Warn("Telegram reply failed", "error", err)
			}
		}
	}
}

// FormatIncident is presentation only; the incident JSON contains machine-readable data.
func FormatIncident(i detector.Incident) string {
	var b strings.Builder
	findings := make([]string, len(i.Findings))
	for n, f := range i.Findings {
		findings[n] = findingName(string(f))
	}
	indicator := "🔴"
	if i.Status == detector.Resolved {
		indicator = "🟢"
	}
	fmt.Fprintf(&b, "%s Инцидент %s · %s\nНачало: %s\nФакты: %s\n", indicator, i.ID, i.Status, formatTime(i.StartedAt), strings.Join(findings, ", "))
	fmt.Fprintf(&b, "%s: %.2f; baseline: %.2f; threshold: %.2f; peak: %.2f\n", metricName(i.Trigger.Metric), i.Trigger.Observed, i.Trigger.Baseline, i.Trigger.Threshold, i.Peak)
	if i.Trigger.IntervalSeconds > 0 {
		fmt.Fprintf(&b, "Интервал измерения: %.1f с\n", i.Trigger.IntervalSeconds)
	}
	if i.SQLRegression != nil {
		r := i.SQLRegression
		fmt.Fprintf(&b, "\nSQL %s\nСреднее: %.2f ms/вызов; baseline: %.2f ms\nВызовов/s: %.2f; baseline: %.2f\n", r.QueryID, r.MeanExecMS, i.Trigger.Baseline, r.CallsPerSecond, r.BaselineCallsPerSecond)
		if r.Status == "unknown" {
			b.WriteString("Недостаточно данных, чтобы оценить восстановление\n")
		}
		fmt.Fprintf(&b, "Последнее SQL-наблюдение: %s\n", formatTime(r.LastObservedAt))
	}
	for n, root := range i.Blockers {
		if n == 3 {
			fmt.Fprintf(&b, "Ещё блокировщиков: %d\n", len(i.Blockers)-n)
			break
		}
		fmt.Fprintf(&b, "\n🔒 PID %d — корневой блокировщик других сессий\n", root.PID)
		if i.BlockingGraph != nil {
			for _, session := range i.BlockingGraph.Nodes {
				if session.PID == root.PID {
					fmt.Fprintf(&b, "%s · %s · возраст транзакции %.1f с\n", session.Application, sessionStateName(session.State), session.TransactionAgeSeconds)
					break
				}
			}
		}
	}
	for n, q := range i.Queries {
		if n == 2 {
			break
		}
		var d struct {
			SQL    string `json:"sql"`
			Source string `json:"query_source"`
		}
		if json.Unmarshal(q.Details, &d) == nil && d.SQL != "" {
			text := []rune(d.SQL)
			if len(text) > 500 {
				text = append(text[:500], []rune("… (полностью в JSON)")...)
			}
			fmt.Fprintf(&b, "\nSQL %s · PID %d · %s:\n%s\n", q.Role, q.PID, d.Source, string(text))
		}
	}

	fmt.Fprintf(&b, "\nВосстановление: %d/%d; пропусков: %d", i.Recovery.NormalSamples, i.Recovery.RequiredSamples, i.DataGaps)
	if i.ResolvedAt != nil {
		fmt.Fprintf(&b, "\nВосстановление подтверждено: %s", formatTime(*i.ResolvedAt))
	}
	return LimitText(b.String(), 3000)
}
