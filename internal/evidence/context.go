package evidence

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/makeev/db-regression-hunter/internal/detector"
)

const (
	maxTables  = 6
	maxIndexes = 6
	maxHeld    = 6
	maxQuery   = 1500
	planLines  = 20
	aliasNote  = "identifiers are replaced with aliases id_N that are unique only within one incident (names_from); literals and comments are removed"
)

type Table struct {
	ID                   string   `json:"id"`
	NamesFrom            string   `json:"names_from"`
	Name                 string   `json:"table"`
	EstimatedRows        float64  `json:"estimated_rows"`
	TotalBytes           float64  `json:"total_bytes"`
	DeadTuples           float64  `json:"dead_tuples"`
	ModifiedSinceAnalyze float64  `json:"modifications_since_analyze"`
	LastAnalyze          string   `json:"last_analyze,omitempty"`
	Indexes              []string `json:"indexes,omitempty"`
}

type details struct {
	SQL         string         `json:"sql"`
	Plan        map[string]any `json:"plan"`
	Reasons     []string       `json:"incomplete_reasons"`
	QuerySource string         `json:"query_source"`
	Locks       []struct {
		Mode    string `json:"mode"`
		Granted bool   `json:"granted"`
		Table   string `json:"table"`
	} `json:"locks"`
}

func parseDetails(q detector.QueryEvidence) (details, bool) {
	var d details
	return d, len(q.Details) > 0 && json.Unmarshal(q.Details, &d) == nil
}

func (p *Package) addQueryContext(incidents []detector.Incident) {
	type sessionQuery struct {
		from string
		d    details
	}
	sessions := map[int]sessionQuery{}
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
			if _, seen := sessions[q.PID]; q.PID != 0 && !seen {
				sessions[q.PID] = sessionQuery{from, d}
			}
		}
		p.addTables(i.Tables, from)
		if p.Settings == nil && len(i.Settings) > 0 {
			json.Unmarshal(i.Settings, &p.Settings)
		}
	}
	for n := range p.Locks {
		s, ok := sessions[p.Locks[n].BlockingPID]
		if !ok {
			continue
		}
		l := &p.Locks[n]
		l.BlockingQuery, l.QuerySource, l.NamesFrom = clip(s.d.SQL), s.d.QuerySource, s.from
		for _, k := range s.d.Locks {
			if k.Granted && k.Table != "" && len(l.HeldLocks) < maxHeld {
				l.HeldLocks = append(l.HeldLocks, k.Mode+" on "+k.Table)
			}
		}
	}
	if collected {
		p.SQLNames = aliasNote
	} else if len(p.Locks) > 0 || len(p.Statements) > 0 {
		p.MissingSources = append(p.MissingSources, "SQL texts, plans and table metadata were not collected for these incidents")
	}
}

func (p *Package) addTables(raw json.RawMessage, from string) {
	var tables []map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &tables) != nil {
		return
	}
	for _, t := range tables {
		if len(p.Tables) == maxTables {
			p.MissingSources = append(p.MissingSources, fmt.Sprintf("only the first %d tables are included", maxTables))
			return
		}
		e := Table{ID: fmt.Sprintf("T%d", len(p.Tables)+1), NamesFrom: from, Name: text(t, "schema") + "." + text(t, "name"),
			EstimatedRows: number(t, "estimated_rows"), TotalBytes: number(t, "total_bytes"), DeadTuples: number(t, "dead_tuples"),
			ModifiedSinceAnalyze: number(t, "modifications_since_analyze"), LastAnalyze: max(text(t, "last_analyze"), text(t, "last_autoanalyze"))}
		indexes, _ := t["indexes"].([]any)
		for _, ix := range indexes {
			if m, ok := ix.(map[string]any); ok && len(e.Indexes) < maxIndexes {
				e.Indexes = append(e.Indexes, clip(text(m, "definition")))
			}
		}
		p.Tables = append(p.Tables, e)
	}
}

func planText(root map[string]any) string {
	var lines []string
	var walk func(map[string]any, int)
	walk = func(n map[string]any, depth int) {
		if len(lines) > planLines {
			return
		}
		if len(lines) == planLines {
			lines = append(lines, "…")
			return
		}
		line := strings.Repeat("  ", depth) + text(n, "Node Type")
		if v := text(n, "Join Type"); v != "" {
			line += " " + v
		}
		if v := text(n, "Relation Name"); v != "" {
			line += " on " + strings.TrimPrefix(text(n, "Schema")+"."+v, ".")
		}
		if v := text(n, "Index Name"); v != "" {
			line += " using " + v
		}
		line += fmt.Sprintf(" (cost=%v rows=%v)", n["Total Cost"], n["Plan Rows"])
		for _, k := range []string{"Index Cond", "Recheck Cond", "Hash Cond", "Merge Cond", "Join Filter", "Filter"} {
			if v := text(n, k); v != "" {
				line += " " + k + ": " + v
			}
		}
		lines = append(lines, line)
		children, _ := n["Plans"].([]any)
		for _, c := range children {
			if m, ok := c.(map[string]any); ok {
				walk(m, depth+1)
			}
		}
	}
	if root != nil {
		walk(root, 0)
	}
	return strings.Join(lines, "\n")
}

func text(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func number(m map[string]any, key string) float64 {
	v, _ := m[key].(float64)
	return value(v)
}

func clip(s string) string {
	if r := []rune(s); len(r) > maxQuery {
		return string(r[:maxQuery]) + " …"
	}
	return s
}
