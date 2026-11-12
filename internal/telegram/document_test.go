package telegram

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/makeev/db-regression-hunter/internal/analysis"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/evidence"
)

func TestAlertsAttachFullLocalContext(t *testing.T) {
	for _, kind := range []string{"incident", "analysis"} {
		t.Run(kind, func(t *testing.T) {
			b := New("test-token", "513", "http://localhost:3000/d/hunter")
			calls := 0
			b.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				switch calls {
				case 1:
					if !strings.HasSuffix(r.URL.Path, "sendMessage") {
						t.Fatal(r.URL.Path)
					}
					var payload struct {
						Text      string `json:"text"`
						ParseMode string `json:"parse_mode"`
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					if payload.ParseMode != "HTML" || (kind == "incident" && !strings.Contains(payload.Text, ">Ссылка на окно в Grafana</a>")) {
						t.Fatal("attachment delivery lost HTML summary", payload)
					}
				case 2:
					if !strings.HasSuffix(r.URL.Path, "sendDocument") {
						t.Fatal(r.URL.Path)
					}
					if err := r.ParseMultipartForm(8 << 20); err != nil {
						t.Fatal(err)
					}
					defer r.MultipartForm.RemoveAll()
					if r.FormValue("chat_id") != "513" {
						t.Fatal("wrong recipient")
					}
					file, header, err := r.FormFile("document")
					if err != nil {
						t.Fatal(err)
					}
					defer file.Close()
					data, err := io.ReadAll(file)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.HasSuffix(header.Filename, ".json") || !json.Valid(data) || !strings.Contains(string(data), "PrivateLedger") || !strings.Contains(string(data), "literal-secret") {
						t.Fatal("attachment lost full local context", string(data))
					}
				default:
					t.Fatal("unexpected requests")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":{}}`))}, nil
			})
			var err error
			if kind == "incident" {
				i := detector.Incident{ID: "42", Status: detector.Open, Queries: []detector.QueryEvidence{{Role: "root_blocker", Details: json.RawMessage(`{"sql":"SELECT * FROM PrivateLedger WHERE value='literal-secret'"}`)}}}
				err = b.Notify(context.Background(), i)
			} else {
				p := evidence.Package{Locks: []evidence.Lock{{BlockingQuery: `SELECT * FROM PrivateLedger WHERE value='literal-secret'`}}}
				err = b.NotifyAnalysis(context.Background(), analysis.Result{ID: "42", Status: analysis.Done, Evidence: &p, Analysis: &analysis.Analysis{Summary: "Проверить транзакцию"}})
			}
			if err != nil || calls != 2 {
				t.Fatal(err, calls)
			}
		})
	}
}
