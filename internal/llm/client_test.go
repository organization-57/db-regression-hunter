package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "obk-test-0123456789abcdef"

func server(t *testing.T, handler func(w http.ResponseWriter, body map[string]any, call int)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testKey || r.URL.Path != "/v1/chat/completions" {
			http.Error(w, "bad auth or path", http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		handler(w, body, int(calls.Add(1)))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func answer(content, reasoning string) string {
	data, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{"message": map[string]any{"content": content, "reasoning_content": reasoning}, "finish_reason": "stop"}},
		"usage":   map[string]any{"prompt_tokens": 1000, "completion_tokens": 500, "completion_tokens_details": map[string]any{"reasoning_tokens": 200}},
	})
	return string(data)
}

func client(srv *httptest.Server, timeout time.Duration) *Client {
	return New(Config{BaseURL: srv.URL + "/v1/", APIKey: testKey, Timeout: timeout})
}

func TestRequestBodyAndUsage(t *testing.T) {
	srv, calls := server(t, func(w http.ResponseWriter, body map[string]any, call int) {
		if body["response_format"].(map[string]any)["type"] != "json_object" || body["model"] != "m" || body["max_tokens"].(float64) != 4096 {
			t.Errorf("request body %v", body)
		}
		w.Write([]byte(answer("<think>plan</think>{\"ok\":true}", "thinking")))
	})
	r, err := client(srv, time.Second).Chat(context.Background(), Request{Model: "m", JSON: true, Messages: []Message{{Role: "user", Content: "x"}}})
	if err != nil || calls.Load() != 1 || r.Content != `{"ok":true}` || r.ReasoningTokens != 200 || r.PromptTokens != 1000 || r.Model != "m" {
		t.Fatalf("reply %+v err %v", r, err)
	}
}

func TestErrorsAreClassifiedAndNeverLeakTheKey(t *testing.T) {
	status := http.StatusServiceUnavailable
	srv, calls := server(t, func(w http.ResponseWriter, body map[string]any, call int) {
		http.Error(w, strings.Repeat("x", 287)+" "+testKey, status)
	})
	_, err := client(srv, time.Second).Chat(context.Background(), Request{Model: "m"})
	var ge *Error
	if !errors.As(err, &ge) || ge.Kind != KindTransient || calls.Load() != 1 {
		t.Fatalf("503 must be transient and not retried by the client: %v", err)
	}
	status = http.StatusUnauthorized
	_, err = client(srv, time.Second).Chat(context.Background(), Request{Model: "m"})
	if !errors.As(err, &ge) || ge.Kind != KindRejected || ge.Status != 401 {
		t.Fatalf("401 must be rejected: %v", err)
	}
	if strings.Contains(err.Error(), testKey[:10]) {
		t.Fatalf("a prefix of the key leaked at the snippet boundary: %v", err)
	}
}

func TestSlowAnswerIsATimeout(t *testing.T) {
	srv, _ := server(t, func(w http.ResponseWriter, body map[string]any, call int) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte(answer("{}", "")))
	})
	_, err := client(srv, 50*time.Millisecond).Chat(context.Background(), Request{Model: "m"})
	var ge *Error
	if !errors.As(err, &ge) || ge.Kind != KindTimeout {
		t.Fatalf("err %v", err)
	}
}

func TestThinkBlocksAreSeparatedFromTheAnswer(t *testing.T) {
	cases := map[string][2]string{
		"<think>plan {a}</think>\n{\"x\":1}":   {`{"x":1}`, "plan {a}"},
		"<think>never closed {\"x\":2}":        {"", "never closed {\"x\":2}"},
		"opening tag missing</think>{\"x\":3}": {`{"x":3}`, "opening tag missing"},
		"{\"x\":4}":                            {`{"x":4}`, ""},
	}
	for in, want := range cases {
		answer, thought := SplitThink(in)
		if answer != want[0] || thought != want[1] {
			t.Errorf("SplitThink(%q) = %q, %q", in, answer, thought)
		}
	}
}

func TestJSONIsFoundInFencesProseAndThink(t *testing.T) {
	cases := map[string]string{
		"```json\n{\"a\":\"}\",\"b\":{\"c\":1}}\n```":            `{"a":"}","b":{"c":1}}`,
		"Here you go: {\"a\":1} hope it helps":                   `{"a":1}`,
		"<think>{\"draft\":true}</think>{\"final\":{\"x\":[1]}}": `{"final":{"x":[1]}}`,
		"{\"a\":\"escaped \\\" quote {\"}":                       `{"a":"escaped \" quote {"}`,
		"{\"small\":1} and {\"bigger\":{\"n\":2}}":               `{"bigger":{"n":2}}`,
	}
	for in, want := range cases {
		got, err := ExtractJSON(in)
		if err != nil || string(got) != want {
			t.Errorf("ExtractJSON(%q) = %s, %v", in, got, err)
		}
	}
	if _, err := ExtractJSON("<think>only thoughts</think> no object"); !errors.Is(err, ErrNoJSON) {
		t.Fatalf("err %v", err)
	}
}
