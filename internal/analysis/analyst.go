package analysis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/makeev/db-regression-hunter/internal/evidence"
	"github.com/makeev/db-regression-hunter/internal/llm"
)

type Chatter interface {
	Chat(ctx context.Context, req llm.Request) (llm.Reply, error)
}

type Analyst struct {
	Client       Chatter
	Models       []string
	Deadline     time.Duration
	HedgeAfter   time.Duration
	RepairRounds int
	Waves        int
	MinWave      time.Duration
}

type outcome struct {
	model    string
	analysis Analysis
	warnings []string
	ok       bool
}

type ledger struct {
	mu       sync.Mutex
	attempts []Attempt
	usage    Usage
}

func (l *ledger) record(a Attempt, r llm.Reply) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts = append(l.attempts, a)
	l.usage.add(Usage{PromptTokens: r.PromptTokens, CompletionTokens: r.CompletionTokens, ReasoningTokens: r.ReasoningTokens})
}

func (a *Analyst) Analyze(ctx context.Context, p evidence.Package) Result {
	start := time.Now()
	r := Result{IncidentIDs: p.IncidentIDs(), StartedAt: start.UTC(), Evidence: &p}
	if a.Deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.Deadline)
		defer cancel()
	}
	won, l := a.race(ctx, p)
	l.mu.Lock()
	r.Attempts, r.Usage = l.attempts, l.usage
	l.mu.Unlock()
	if won.ok {
		analysis := won.analysis
		r.Status, r.Model, r.Analysis, r.Warnings = Done, won.model, &analysis, won.warnings
	} else {
		r.Status, r.Error = Failed, failure(ctx, a.Deadline, r.Attempts)
	}
	finished := time.Now().UTC()
	r.FinishedAt, r.LatencyMs = &finished, time.Since(start).Milliseconds()
	return r
}

func failure(ctx context.Context, deadline time.Duration, attempts []Attempt) string {
	if len(attempts) == 0 {
		return "no model was called"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Sprintf("no valid answer within %s", deadline)
	}
	last := attempts[len(attempts)-1]
	if last.Detail != "" {
		return last.Model + ": " + last.Detail
	}
	return last.Model + ": " + strings.Join(last.Errors, "; ")
}

func (a *Analyst) race(ctx context.Context, p evidence.Package) (outcome, *ledger) {
	l := &ledger{}
	if len(a.Models) == 0 {
		return outcome{}, l
	}
	ctx, cancel := context.WithCancel(ctx)
	results := make(chan outcome, len(a.Models)*max(1, a.Waves))
	var wg sync.WaitGroup
	launched, running, wave := 0, 0, 1
	launch := func() {
		model := a.Models[launched]
		launched++
		running++
		wg.Add(1)
		go func(wave int) {
			defer wg.Done()
			results <- a.tryModel(ctx, p, model, wave, l)
		}(wave)
	}
	defer func() {
		cancel()
		wg.Wait()
	}()
	launch()
	for {
		hedge := make(<-chan time.Time)
		var timer *time.Timer
		if a.HedgeAfter > 0 && launched < len(a.Models) {
			timer = time.NewTimer(a.HedgeAfter)
			hedge = timer.C
		}
		stop := func() {
			if timer != nil {
				timer.Stop()
			}
		}
		select {
		case r := <-results:
			stop()
			running--
			if r.ok {
				return r, l
			}
			switch {
			case ctx.Err() != nil:
				if running == 0 {
					return outcome{}, l
				}
			case launched < len(a.Models):
				launch()
			case running == 0 && wave < a.Waves && a.timeLeft(ctx):
				wave, launched = wave+1, 0
				launch()
			case running == 0:
				return outcome{}, l
			}
		case <-hedge:
			launch()
		case <-ctx.Done():
			stop()
			return outcome{}, l
		}
	}
}

func (a *Analyst) timeLeft(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	return !ok || time.Until(deadline) >= a.MinWave
}

func (a *Analyst) tryModel(ctx context.Context, p evidence.Package, model string, wave int, l *ledger) outcome {
	messages := conversation(p)
	for round := 0; round <= a.RepairRounds; round++ {
		reply, err := a.Client.Chat(ctx, llm.Request{Model: model, Messages: messages, JSON: true})
		attempt := Attempt{Model: model, Wave: wave, Round: round, LatencyMs: reply.Latency.Milliseconds()}
		if err != nil {
			attempt.Outcome, attempt.Detail = "error", err.Error()
			var le *llm.Error
			switch {
			case ctx.Err() != nil:
				attempt.Outcome, attempt.Detail = "cancelled", "another model answered first or the deadline passed"
			case errors.As(err, &le):
				attempt.Outcome = string(le.Kind)
			}
			l.record(attempt, reply)
			return outcome{model: model}
		}
		analysis, warnings, problems := judge(reply, p)
		if len(problems) == 0 {
			attempt.Outcome = "valid"
			l.record(attempt, reply)
			return outcome{model: model, analysis: analysis, warnings: warnings, ok: true}
		}
		attempt.Outcome, attempt.Errors, attempt.Excerpt = "invalid", problems, excerpt(reply.Content)
		l.record(attempt, reply)
		messages = append(messages, llm.Message{Role: "assistant", Content: reply.Content}, llm.Message{Role: "user", Content: repairPrompt(problems)})
	}
	return outcome{model: model}
}

func judge(reply llm.Reply, p evidence.Package) (Analysis, []string, []string) {
	raw, err := llm.ExtractJSON(reply.Content)
	if err != nil {
		if reply.FinishReason == "length" {
			return Analysis{}, nil, []string{"the answer was cut off by the token limit: be shorter"}
		}
		return Analysis{}, nil, []string{err.Error() + ": reply with one JSON object"}
	}
	a, err := parse(raw)
	if err != nil {
		return a, nil, []string{"JSON does not match the shape: " + err.Error()}
	}
	v := check(&a, p)
	return a, v.warnings, v.errors
}

func excerpt(s string) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > 600 {
		return string(r[:600]) + "…"
	}
	return string(r)
}
