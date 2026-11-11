package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/makeev/db-regression-hunter/internal/analysis"
	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/config"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/evidence"
	"github.com/makeev/db-regression-hunter/internal/telegram"
)

const (
	analysisGap     = 2 * time.Minute
	telegramMaxText = 4000
)

type llmLayer struct {
	analyst *analysis.Analyst
	batcher *analysis.Batcher
	history *evidence.History
	results analysis.Results
	pg      *collector.Postgres
	sqlText bool
	bot     *telegram.Bot
	wg      *sync.WaitGroup
	busy    atomic.Bool
	seq     int
}

func newLLM(cfg config.LLM, pg *collector.Postgres, wg *sync.WaitGroup) *llmLayer {
	if !cfg.Enabled() {
		slog.Info("LLM analysis disabled: GONKA_API_KEY is not set")
		return nil
	}
	slog.Info("LLM analysis enabled", "base_url", cfg.BaseURL, "models", cfg.Models, "delay", cfg.Delay, "sql_text", cfg.SQLText)
	return &llmLayer{
		analyst: analysis.NewAnalyst(cfg),
		batcher: analysis.NewBatcher(cfg.Delay, analysisGap),
		history: evidence.NewHistory(120),
		pg:      pg,
		sqlText: cfg.SQLText,
		wg:      wg,
	}
}

func (l *llmLayer) notify(bot *telegram.Bot) {
	if l != nil {
		l.bot = bot
	}
}

func (l *llmLayer) observe(ctx context.Context, s collector.Snapshot, updates []*detector.Incident) {
	if l == nil {
		return
	}
	during := false
	for _, u := range updates {
		if u.Finding != detector.FindingSQLExecutionRegression && u.Status != detector.Resolved {
			during = true
		}
	}
	l.history.Add(s, during)
	batch := l.batcher.Observe(updates, time.Now(), l.busy.Load())
	if len(batch) == 0 {
		return
	}
	p := evidence.Build(batch, l.history, s)
	l.seq++
	id := fmt.Sprint(l.seq)
	l.results.Put(analysis.NewResult(id, p))
	l.busy.Store(true)
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		defer l.busy.Store(false)
		p.Enrich(ctx, l.pg, l.sqlText)
		r := l.analyst.Analyze(ctx, p)
		r.ID = id
		l.results.Put(r)
		slog.Info("incident analysis", "id", id, "incidents", r.IncidentIDs, "status", r.Status, "reason", r.Reason, "model", r.Model,
			"latency_ms", r.LatencyMs, "attempts", len(r.Attempts), "error", r.Error)
		if l.bot != nil && ctx.Err() == nil {
			if err := l.bot.Send(ctx, telegram.FormatAnalysis(r)); err != nil {
				slog.Warn("analysis notification failed", "error", err)
			}
		}
	}()
}

func (l *llmLayer) withAnalysis(text, incidentID string) string {
	if l == nil {
		return text
	}
	if r, ok := l.results.ForIncident(incidentID); ok {
		text += "\n\n" + telegram.FormatAnalysis(r)
	}
	if runes := []rune(text); len(runes) > telegramMaxText {
		text = string(runes[:telegramMaxText-1]) + "…"
	}
	return text
}

func (l *llmLayer) handler(next http.Handler) http.Handler {
	if l == nil {
		return next
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/analyses", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(l.results.All())
	})
	mux.Handle("/", next)
	return mux
}
