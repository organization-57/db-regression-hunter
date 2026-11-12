package evidence

import (
	"encoding/json"
	"fmt"

	"github.com/makeev/db-regression-hunter/internal/redact"
)

// ForLLM is the only export boundary. Build and stored results keep full local
// context; the prompt receives an independent, allowlisted, anonymized copy.
func (p Package) ForLLM() (Package, redact.Context, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return Package{}, nil, err
	}
	var safe Package
	if err = json.Unmarshal(data, &safe); err != nil {
		return Package{}, nil, err
	}
	a := redact.New()
	safe.Settings = nil
	for _, key := range []string{"server_version_num", "work_mem", "effective_cache_size", "random_page_cost", "seq_page_cost", "effective_io_concurrency", "max_parallel_workers_per_gather", "jit", "default_statistics_target"} {
		if v, ok := p.Settings[key]; ok {
			if safe.Settings == nil {
				safe.Settings = map[string]string{}
			}
			safe.Settings[key] = v
		}
	}
	seenMissing := map[string]bool{}
	for _, s := range safe.MissingSources {
		seenMissing[s] = true
	}
	missing := func(id, field string) {
		msg := fmt.Sprintf("%s %s omitted during anonymization", id, field)
		if !seenMissing[msg] {
			safe.MissingSources = append(safe.MissingSources, msg)
			seenMissing[msg] = true
		}
	}
	sql := func(s, id, field string) string {
		if s == "" {
			return ""
		}
		v, err := a.SQL(s)
		if err != nil {
			missing(id, field)
			return ""
		}
		return v
	}
	plan := func(raw map[string]any, id string) map[string]any {
		clean := a.Plan(raw)
		if incompletePlan(raw, clean) {
			missing(id, "plan fields")
		}
		return clean
	}
	refs := map[string]string{}
	for n := range safe.Tables {
		t := &safe.Tables[n]
		original := t.QualifiedName()
		t.Schema, t.Name = a.Name(t.Schema), a.Name(t.Name)
		refs[original] = t.Schema + "." + t.Name
		for k := range t.Columns {
			c := &t.Columns[k]
			c.Name = a.Name(c.Name)
			if typ, err := a.Type(c.Type); err == nil {
				c.Type = typ
			} else {
				c.Type = ""
				missing(t.ID, "column type")
			}
		}
		for k := range t.Indexes {
			t.Indexes[k].Definition = sql(t.Indexes[k].Definition, t.ID, "index")
		}
		for k := range t.Constraints {
			t.Constraints[k] = sql(t.Constraints[k], t.ID, "constraint")
		}
	}
	for n := range safe.Locks {
		l := &safe.Locks[n]
		l.BlockingApplication = a.Name(l.BlockingApplication)
		l.Plan = plan(l.Plan, l.ID)
		l.BlockingQuery = sql(l.BlockingQuery, l.ID, "SQL")
		for k := range l.HeldLocks {
			lock := &l.HeldLocks[k]
			if ref, ok := refs[lock.Table]; ok {
				lock.Table = ref
			} else {
				lock.Table = sql(lock.Table, l.ID, "lock relation")
			}
		}
	}
	for n := range safe.Statements {
		q := &safe.Statements[n]
		q.Plan = plan(q.Plan, q.ID)
		q.Query = sql(q.Query, q.ID, "SQL")
	}
	for n := range safe.Sessions {
		safe.Sessions[n].Application = a.Name(safe.Sessions[n].Application)
	}
	safe.SQLNames = "identifiers and application names use aliases id_N unique within this package; literals and comments are removed; names_from identifies the source incident"
	return safe, a, nil
}

func incompletePlan(raw, clean map[string]any) bool {
	for key, value := range raw {
		got, ok := clean[key]
		if !ok {
			return true
		}
		if s, ok := got.(string); ok && s == "redacted" {
			return true
		}
		if xs, ok := got.([]string); ok {
			original, _ := value.([]any)
			if len(original) != len(xs) {
				return true
			}
			for _, s := range xs {
				if s == "redacted" {
					return true
				}
			}
		}
		if key == "Plans" {
			original, _ := value.([]any)
			children, _ := got.([]map[string]any)
			if len(original) != len(children) {
				return true
			}
			for n, child := range original {
				node, ok := child.(map[string]any)
				if !ok || incompletePlan(node, children[n]) {
					return true
				}
			}
		}
	}
	return false
}
