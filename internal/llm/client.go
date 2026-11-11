package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	BaseURL     string
	APIKey      string
	Timeout     time.Duration
	MaxTokens   int
	Temperature float64
	Extra       map[string]any
	HTTP        *http.Client
}

type Client struct{ cfg Config }

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Request struct {
	Model    string
	Messages []Message
	JSON     bool
}

type Reply struct {
	Model            string
	Content          string
	FinishReason     string
	PromptTokens     int
	CompletionTokens int
	ReasoningTokens  int
	Latency          time.Duration
}

type ErrorKind string

const (
	KindTransient ErrorKind = "transient"
	KindRejected  ErrorKind = "rejected"
	KindTimeout   ErrorKind = "timeout"
)

type Error struct {
	Kind   ErrorKind
	Status int
	Msg    string
}

func (e *Error) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("gonka %s: HTTP %d: %s", e.Kind, e.Status, e.Msg)
	}
	return fmt.Sprintf("gonka %s: %s", e.Kind, e.Msg)
}

func New(cfg Config) *Client {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 90 * time.Second
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 4096
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Client{cfg: cfg}
}

func (c *Client) Chat(ctx context.Context, req Request) (Reply, error) {
	start := time.Now()
	r, err := c.once(ctx, req)
	r.Model, r.Latency = req.Model, time.Since(start)
	return r, err
}

type wireResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens            int `json:"prompt_tokens"`
		CompletionTokens        int `json:"completion_tokens"`
		CompletionTokensDetails struct {
			ReasoningTokens int `json:"reasoning_tokens"`
		} `json:"completion_tokens_details"`
	} `json:"usage"`
}

func (c *Client) once(ctx context.Context, req Request) (Reply, error) {
	body := map[string]any{}
	for k, v := range c.cfg.Extra {
		body[k] = v
	}
	body["model"], body["messages"], body["max_tokens"], body["temperature"] = req.Model, req.Messages, c.cfg.MaxTokens, c.cfg.Temperature
	if req.JSON {
		body["response_format"] = map[string]string{"type": "json_object"}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return Reply{}, err
	}
	actx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	hreq, err := http.NewRequestWithContext(actx, http.MethodPost, c.cfg.BaseURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return Reply{}, &Error{Kind: KindRejected, Msg: "invalid GONKA_BASE_URL"}
	}
	hreq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := c.cfg.HTTP.Do(hreq)
	if err != nil {
		if actx.Err() != nil && ctx.Err() == nil {
			return Reply{}, &Error{Kind: KindTimeout, Msg: fmt.Sprintf("no answer within %s", c.cfg.Timeout)}
		}
		return Reply{}, &Error{Kind: KindTransient, Msg: c.redact(err.Error())}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		if actx.Err() != nil && ctx.Err() == nil {
			return Reply{}, &Error{Kind: KindTimeout, Msg: fmt.Sprintf("no answer within %s", c.cfg.Timeout)}
		}
		return Reply{}, &Error{Kind: KindTransient, Msg: c.redact(err.Error())}
	}
	if resp.StatusCode != http.StatusOK {
		kind := KindRejected
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			kind = KindTransient
		}
		return Reply{}, &Error{Kind: kind, Status: resp.StatusCode, Msg: snippet(c.redact(string(raw)))}
	}
	var w wireResponse
	if err := json.Unmarshal(raw, &w); err != nil || len(w.Choices) == 0 {
		return Reply{}, &Error{Kind: KindTransient, Msg: "malformed response: " + snippet(c.redact(string(raw)))}
	}
	ch := w.Choices[0]
	content, _ := SplitThink(ch.Message.Content)
	r := Reply{
		Content:          content,
		FinishReason:     ch.FinishReason,
		PromptTokens:     w.Usage.PromptTokens,
		CompletionTokens: w.Usage.CompletionTokens,
		ReasoningTokens:  w.Usage.CompletionTokensDetails.ReasoningTokens,
	}
	return r, nil
}

func (c *Client) redact(s string) string {
	if c.cfg.APIKey != "" {
		s = strings.ReplaceAll(s, c.cfg.APIKey, "[redacted]")
	}
	return s
}

func snippet(raw string) string {
	s := strings.Join(strings.Fields(raw), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
