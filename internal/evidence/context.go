package evidence

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/detector"
)

const maxTables = 6
const maxHeld = 6

type Column struct {
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	NotNull          bool     `json:"not_null"`
	NullFraction     *float64 `json:"null_fraction"`
	DistinctEstimate *float64 `json:"distinct_estimate"`
	AverageWidth     *float64 `json:"avg_width"`
	Correlation      *float64 `json:"correlation"`
}

type Index struct {
	Definition string `json:"definition"`
	Valid      bool   `json:"valid"`
}

type Table struct {
	ID                   string     `json:"id"`
	NamesFrom            string     `json:"names_from"`
	ObservedAt           *time.Time `json:"observed_at,omitempty"`
	Schema               string     `json:"schema"`
	Name                 string     `json:"table"`
	EstimatedRows        float64    `json:"estimated_rows"`
	HeapBytes            float64    `json:"heap_bytes"`
	TotalBytes           float64    `json:"total_bytes"`
	IndexBytes           float64    `json:"index_bytes"`
	LiveTuples           *float64   `json:"live_tuples"`
	DeadTuples           *float64   `json:"dead_tuples"`
	ModifiedSinceAnalyze *float64   `json:"modifications_since_analyze"`
	LastAnalyze          string     `json:"last_analyze,omitempty"`
	LastAutoanalyze      string     `json:"last_autoanalyze,omitempty"`
	LastVacuum           string     `json:"last_vacuum,omitempty"`
	LastAutovacuum       string     `json:"last_autovacuum,omitempty"`
	Columns              []Column   `json:"columns"`
	Indexes              []Index    `json:"indexes"`
	Constraints          []string   `json:"constraints"`
	ColumnsTruncated     bool       `json:"columns_truncated,omitempty"`
	IndexesTruncated     bool       `json:"indexes_truncated,omitempty"`
	ConstraintsTruncated bool       `json:"constraints_truncated,omitempty"`
}

func (t Table) QualifiedName() string { return collector.RelationRef(t.Schema, t.Name) }

type HeldLock struct {
	Mode  string `json:"mode"`
	Table string `json:"table,omitempty"`
}

type details struct {
	At          time.Time      `json:"at"`
	SQL         string         `json:"sql"`
	Plan        map[string]any `json:"plan"`
	PlanKind    string         `json:"plan_kind"`
	Reasons     []string       `json:"incomplete_reasons"`
	QuerySource string         `json:"query_source"`
	TableScope  string         `json:"table_scope"`
	Locks       []struct {
		Mode    string `json:"mode"`
		Granted bool   `json:"granted"`
		Table   string `json:"table"`
	} `json:"locks"`
}

func parseDetails(q detector.QueryEvidence) (details, bool) {
	var d details
	ok := len(q.Details) > 0 && json.Unmarshal(q.Details, &d) == nil
	return d, ok
}

type sessionKey struct {
	pid                         int
	backend, query, transaction time.Time
	state                       string
}

func stamp(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC().Round(0)
}
func key(pid int, backend, query, transaction *time.Time, state string) sessionKey {
	return sessionKey{pid, stamp(backend), stamp(query), stamp(transaction), state}
}

func (p *Package) addQueryContext(incidents []detector.Incident) {
	type observed struct {
		from string
		d    details
	}
	sessions := map[sessionKey]observed{}
	collected := false
	for n, i := range incidents {
		from := p.Incidents[n].ID
		for _, q := range i.Queries {
			d, ok := parseDetails(q)
			if !ok {
				continue
			}
			collected = true
			if len(d.Reasons) > 0 {
				p.MissingSources = append(p.MissingSources, fmt.Sprintf("SQL context of %s %s is incomplete: %s", from, q.Role, strings.Join(d.Reasons, ", ")))
			}
			if q.PID == 0 || q.BackendStart == nil || q.QueryStart == nil || d.At.IsZero() {
				continue
			}
			k := key(q.PID, q.BackendStart, q.QueryStart, q.TransactionStart, q.State)
			if prior, ok := sessions[k]; !ok || prior.d.At.Before(d.At) {
				sessions[k] = observed{from, d}
			}
		}
		p.addTables(i.Tables, from)
		if p.Settings == nil && len(i.Settings) > 0 {
			json.Unmarshal(i.Settings, &p.Settings)
		}
	}
	for n := range p.Locks {
		l := &p.Locks[n]
		if l.BackendStart == nil || l.QueryStart == nil {
			p.MissingSources = append(p.MissingSources, "session identity is incomplete for "+l.ID)
			continue
		}
		s, ok := sessions[key(l.BlockingPID, l.BackendStart, l.QueryStart, l.TransactionStart, l.BlockingState)]
		if !ok {
			p.MissingSources = append(p.MissingSources, "SQL context does not match the session/query/transaction identity of "+l.ID)
			continue
		}
		if s.d.At.Before(*l.QueryStart) {
			p.MissingSources = append(p.MissingSources, "SQL context predates query start for "+l.ID)
			continue
		}
		l.BlockingQuery, l.QuerySource, l.NamesFrom = s.d.SQL, s.d.QuerySource, s.from
		l.QueryObservedAt = &s.d.At
		l.Plan, l.PlanKind = s.d.Plan, s.d.PlanKind
		l.TableScope = s.d.TableScope
		for _, k := range s.d.Locks {
			if k.Granted && k.Table != "" {
				if len(l.HeldLocks) == maxHeld {
					p.MissingSources = append(p.MissingSources, "held lock list truncated for "+l.ID)
					break
				}
				l.HeldLocks = append(l.HeldLocks, HeldLock{k.Mode, k.Table})
			}
		}
	}
	if !collected && (len(p.Locks) > 0 || len(p.Statements) > 0) {
		p.MissingSources = append(p.MissingSources, "SQL texts, plans and table metadata were not collected for these incidents")
	}
}

func (p *Package) addTables(raw json.RawMessage, from string) {
	var tables []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &tables) != nil {
		return
	}
	for _, data := range tables {
		if len(p.Tables) == maxTables {
			p.MissingSources = append(p.MissingSources, fmt.Sprintf("only the first %d tables are included", maxTables))
			return
		}
		var t Table
		var ref struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(data, &t) != nil || json.Unmarshal(data, &ref) != nil {
			p.MissingSources = append(p.MissingSources, "table metadata could not be decoded for "+from)
			continue
		}
		t.ID, t.NamesFrom, t.Name = fmt.Sprintf("T%d", len(p.Tables)+1), from, ref.Name
		p.Tables = append(p.Tables, t)
	}
}
