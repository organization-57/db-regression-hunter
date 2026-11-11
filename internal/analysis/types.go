package analysis

import (
	"time"

	"github.com/makeev/db-regression-hunter/internal/evidence"
)

const (
	Pending = "pending"
	Done    = "ok"
	Failed  = "failed"
)

var Categories = []string{
	"lock_contention", "long_transaction", "blocking_ddl", "deadlock", "slow_query", "plan_regression",
	"missing_index", "temp_spill", "connection_saturation", "io_cache_miss", "load_growth", "unknown",
}

var (
	priorities = []string{"now", "next", "later"}
	risks      = []string{"low", "medium", "high"}
)

type Analysis struct {
	Summary         string           `json:"summary"`
	RootCauses      []Cause          `json:"root_causes"`
	Checks          []Check          `json:"checks"`
	Recommendations []Recommendation `json:"recommendations"`
	Assumptions     []string         `json:"assumptions"`
	MissingData     []string         `json:"missing_data"`
}

type Cause struct {
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	Confidence  float64  `json:"confidence"`
	Evidence    []string `json:"evidence"`
}

type Check struct {
	Step   string `json:"step"`
	SQL    string `json:"sql,omitempty"`
	Expect string `json:"expect"`
}

type Recommendation struct {
	Action           string   `json:"action"`
	Priority         string   `json:"priority"`
	Risk             string   `json:"risk"`
	SQL              string   `json:"sql,omitempty"`
	Verify           string   `json:"verify"`
	Evidence         []string `json:"evidence"`
	RequiresApproval bool     `json:"requires_approval"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	ReasoningTokens  int `json:"reasoning_tokens"`
}

func (u *Usage) add(o Usage) {
	u.PromptTokens += o.PromptTokens
	u.CompletionTokens += o.CompletionTokens
	u.ReasoningTokens += o.ReasoningTokens
}

type Attempt struct {
	Model     string   `json:"model"`
	Wave      int      `json:"wave"`
	Round     int      `json:"round"`
	LatencyMs int64    `json:"latency_ms"`
	Outcome   string   `json:"outcome"`
	Detail    string   `json:"detail,omitempty"`
	Errors    []string `json:"errors,omitempty"`
	Excerpt   string   `json:"excerpt,omitempty"`
}

type Result struct {
	ID          string            `json:"id"`
	IncidentIDs []string          `json:"incident_ids"`
	Status      string            `json:"status"`
	Model       string            `json:"model,omitempty"`
	StartedAt   time.Time         `json:"started_at"`
	FinishedAt  *time.Time        `json:"finished_at,omitempty"`
	LatencyMs   int64             `json:"latency_ms"`
	Usage       Usage             `json:"usage"`
	Attempts    []Attempt         `json:"attempts"`
	Warnings    []string          `json:"warnings,omitempty"`
	Error       string            `json:"error,omitempty"`
	Analysis    *Analysis         `json:"analysis,omitempty"`
	Evidence    *evidence.Package `json:"evidence,omitempty"`
}
