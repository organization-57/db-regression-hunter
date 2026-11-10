package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/makeev/db-regression-hunter/internal/detector"
)

type Bot struct {
	token, chatID, grafanaURL string
	client                    *http.Client
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
	if result != nil {
		return json.Unmarshal(envelope.Result, result)
	}
	return nil
}

func (b *Bot) Send(ctx context.Context, message string) error {
	return b.call(ctx, "sendMessage", map[string]any{"chat_id": b.chatID, "text": message, "link_preview_options": map[string]bool{"is_disabled": true}}, nil)
}

func (b *Bot) Notify(ctx context.Context, i detector.Incident) error {
	message := FormatIncident(i)
	if b.grafanaURL != "" {
		message += "\n\nGrafana: " + b.grafanaURL
	}
	return b.Send(ctx, message)
}

func (b *Bot) Run(ctx context.Context, status func() string, latest func() string) {
	b.RunWithIncidentLookup(ctx, status, latest, nil)
}

// RunWithIncidentLookup adds ID lookup while preserving the original Run API.
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
			switch command {
			case "/status":
				answer = status()
			case "/incidents":
				answer = latest()
			case "/incident":
				if len(parts) != 2 {
					answer = "Использование: /incident <ID>"
				} else if lookup == nil {
					answer = "Поиск расследований по ID недоступен"
				} else if incident, ok := lookup(parts[1]); ok {
					answer = b.IncidentSummary(incident)
				} else {
					answer = "Расследование не найдено. Хранятся только последние 100 расследований; после перезапуска они теряются."
				}
			case "/start", "/help":
				answer = "/status — состояние PostgreSQL\n/incidents — последнее расследование\n/incident <ID> — расследование по ID"
			default:
				continue
			}
			if err := b.Send(ctx, answer); err != nil {
				slog.Warn("Telegram reply failed", "error", err)
			}
		}
	}
}

// FormatIncident is presentation only; the incident JSON contains machine-readable data.
func FormatIncident(i detector.Incident) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Инцидент %s · %s\nНачало: %s\nСигнал: %s\n", i.ID, i.Status, i.StartedAt.Format(time.RFC3339), i.Finding)
	fmt.Fprintf(&b, "Возраст запроса при обнаружении: %.2f s; baseline: %.2f s; порог: %.2f s\n", i.Trigger.Observed, i.Trigger.Baseline, i.Trigger.Threshold)
	for n, root := range i.Blockers {
		if n == 3 {
			fmt.Fprintf(&b, "Ещё блокировщиков: %d\n", len(i.Blockers)-n)
			break
		}
		fmt.Fprintf(&b, "\nКорневой PID %d\n", root.PID)
		if i.BlockingGraph != nil {
			for _, session := range i.BlockingGraph.Nodes {
				if session.PID == root.PID {
					fmt.Fprintf(&b, "%s · %s · транзакция %.1f s\n", session.Application, session.State, session.TransactionAgeSeconds)
					break
				}
			}
		}
		if len(root.Chains) > 0 {
			chain := []string{}
			for _, pid := range root.Chains[0] {
				chain = append(chain, fmt.Sprint(pid))
			}
			fmt.Fprintf(&b, "Ожидание: %s\n", strings.Join(chain, " → "))
		}
	}
	fmt.Fprintf(&b, "\nПик возраста запросов: %.2f s; ожидающих Lock: %d\nВосстановление: %d/%d; пропусков: %d", i.PeakQuerySeconds, i.PeakLockWaiters, i.Recovery.NormalSamples, i.Recovery.RequiredSamples, i.DataGaps)
	if i.ResolvedAt != nil {
		fmt.Fprintf(&b, "\nВосстановление подтверждено: %s", i.ResolvedAt.Format(time.RFC3339))
	}
	text := []rune(b.String())
	if len(text) > 3000 {
		return string(text[:2990]) + "…"
	}
	return string(text)
}
