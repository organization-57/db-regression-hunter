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
	message := fmt.Sprintf("Расследование %s\nСтатус: %s\nНачало симптомов: %s\n%s\n\nДанные:\n%s\n\nСледующие шаги:\n%s", i.ID, i.Status, i.StartedAt.Format(time.RFC3339), i.Hypothesis, strings.Join(i.Evidence, "\n"), strings.Join(i.NextSteps, "\n"))
	if i.RecoveredAt != nil {
		message += "\n\nВосстановление симптомов БД подтверждено: " + i.RecoveredAt.Format(time.RFC3339)
	}
	if b.grafanaURL != "" {
		message += "\n\nGrafana: " + b.grafanaURL
	}
	return b.Send(ctx, message)
}

func (b *Bot) Run(ctx context.Context, status func() string, latest func() string) {
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
			case "/start", "/help":
				answer = "/status — состояние PostgreSQL\n/incidents — последнее расследование"
			default:
				continue
			}
			if err := b.Send(ctx, answer); err != nil {
				slog.Warn("Telegram reply failed", "error", err)
			}
		}
	}
}
