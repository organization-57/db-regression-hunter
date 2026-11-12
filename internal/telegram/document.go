package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"

	"github.com/makeev/db-regression-hunter/internal/analysis"
)

// Text messages remain readable; the document contains the full local evidence.
func (b *Bot) SendDocument(ctx context.Context, filename string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Telegram document")
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err = w.WriteField("chat_id", b.chatID); err != nil {
		return err
	}
	part, err := w.CreateFormFile("document", filename)
	if err != nil {
		return err
	}
	if _, err = part.Write(data); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+b.token+"/sendDocument", &body)
	if err != nil {
		return fmt.Errorf("build Telegram document request")
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	return b.do(req, nil)
}

func (b *Bot) NotifyAnalysis(ctx context.Context, r analysis.Result) error {
	if _, err := b.post(ctx, FormatAnalysis(r), b.alertFor(r.IncidentIDs)); err != nil {
		return err
	}
	if r.Evidence != nil {
		return b.SendDocument(ctx, "analysis-"+r.ID+".json", r)
	}
	return nil
}
