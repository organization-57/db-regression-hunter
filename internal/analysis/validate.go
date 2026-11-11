package analysis

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/makeev/db-regression-hunter/internal/evidence"
)

type validation struct {
	errors   []string
	warnings []string
}

func parse(raw []byte) (Analysis, error) {
	var a Analysis
	if err := json.Unmarshal(raw, &a); err != nil {
		return a, err
	}
	if a.Summary != "" || len(a.RootCauses) > 0 {
		return a, nil
	}
	var wrapper map[string]json.RawMessage
	if json.Unmarshal(raw, &wrapper) == nil && len(wrapper) == 1 {
		for _, inner := range wrapper {
			var unwrapped Analysis
			if json.Unmarshal(inner, &unwrapped) == nil && (unwrapped.Summary != "" || len(unwrapped.RootCauses) > 0) {
				return unwrapped, nil
			}
		}
	}
	return a, nil
}

func check(a *Analysis, p evidence.Package) validation {
	var v validation
	known := p.IDs()
	roots := p.RootPIDs()
	if strings.TrimSpace(a.Summary) == "" {
		v.errors = append(v.errors, "summary is empty")
	}
	if len(a.RootCauses) == 0 {
		v.errors = append(v.errors, "root_causes is empty")
	}
	for i, c := range a.RootCauses {
		where := fmt.Sprintf("root_causes[%d]", i)
		if !contains(Categories, c.Category) {
			v.errors = append(v.errors, fmt.Sprintf("%s: category %q is not one of %s", where, c.Category, strings.Join(Categories, ", ")))
		}
		if strings.TrimSpace(c.Title) == "" || strings.TrimSpace(c.Explanation) == "" {
			v.errors = append(v.errors, where+": title and explanation are required")
		}
		if c.Confidence < 0 || c.Confidence > 1 || math.IsNaN(c.Confidence) {
			v.errors = append(v.errors, fmt.Sprintf("%s: confidence %v is outside 0..1", where, c.Confidence))
		}
		if len(c.Evidence) == 0 && c.Category != "unknown" {
			v.errors = append(v.errors, where+": evidence is empty")
		}
		for _, ref := range c.Evidence {
			if !known[ref] {
				v.errors = append(v.errors, fmt.Sprintf("%s: unknown evidence id %q; use only ids from the evidence package", where, ref))
			}
		}
		if problem := contradiction(c, p); problem != "" {
			v.errors = append(v.errors, where+": "+problem)
		}
	}
	sort.SliceStable(a.RootCauses, func(x, y int) bool { return a.RootCauses[x].Confidence > a.RootCauses[y].Confidence })
	var checks []Check
	for _, c := range a.Checks {
		switch {
		case c.SQL != "" && !targetsKnownSessions(c.SQL, roots):
			v.warnings = append(v.warnings, "a check that targets sessions outside the evidence was dropped")
		case c.SQL != "" && !IsReadOnlySQL(c.SQL):
			a.Recommendations = append(a.Recommendations, Recommendation{Action: c.Step, Priority: "next", Risk: "medium", SQL: c.SQL, Verify: c.Expect, RequiresApproval: true})
			v.warnings = append(v.warnings, "a check with state-changing SQL was moved to recommendations")
		default:
			checks = append(checks, c)
		}
	}
	a.Checks = checks
	var recs []Recommendation
	for i, r := range a.Recommendations {
		where := fmt.Sprintf("recommendations[%d]", i)
		if r.SQL != "" && !targetsKnownSessions(r.SQL, roots) {
			v.warnings = append(v.warnings, where+" dropped: it terminates or cancels a session that is not a current root blocker")
			continue
		}
		if strings.TrimSpace(r.Action) == "" {
			v.errors = append(v.errors, where+": action is empty")
		}
		if strings.TrimSpace(r.Verify) == "" {
			v.errors = append(v.errors, where+": verify is empty: say which metric shows the effect")
		}
		if !contains(priorities, r.Priority) {
			r.Priority = "next"
		}
		if !contains(risks, r.Risk) {
			r.Risk = "medium"
		}
		var refs []string
		for _, ref := range r.Evidence {
			if known[ref] {
				refs = append(refs, ref)
			}
		}
		r.Evidence = refs
		if IsMutatingSQL(r.SQL) {
			r.RequiresApproval = true
		}
		recs = append(recs, r)
	}
	a.Recommendations = recs
	if len(a.Recommendations) == 0 {
		v.errors = append(v.errors, "recommendations is empty or every recommendation targeted sessions outside the evidence")
	}
	return v
}

func contradiction(c Cause, p evidence.Package) string {
	cited := map[string]bool{}
	for _, ref := range c.Evidence {
		cited[ref] = true
	}
	var citedLock, tableLockWait bool
	for _, l := range p.Locks {
		if !cited[l.ID] {
			continue
		}
		citedLock = true
		for _, e := range l.WaiterWaitEvents {
			if e == "Lock:relation" {
				tableLockWait = true
			}
		}
	}
	finding := func(name string) bool {
		for _, i := range p.Incidents {
			if i.Finding == name {
				return true
			}
		}
		return false
	}
	grew := func(name string) bool {
		for _, m := range p.Metrics {
			if m.Name == name && m.Incident != nil && *m.Incident > 0 && (m.Baseline == nil || *m.Incident > *m.Baseline) {
				return true
			}
		}
		return false
	}
	switch c.Category {
	case "blocking_ddl":
		if !tableLockWait {
			return "category blocking_ddl needs a cited blocker whose waiters wait for Lock:relation (a table-level lock); with row-level waits (transactionid, tuple) use long_transaction or lock_contention"
		}
	case "long_transaction":
		if !citedLock {
			return "category long_transaction needs a cited blocker (L*) that others wait for; without lock waits a long-running statement is slow_query"
		}
	case "lock_contention":
		waiting := false
		for _, m := range p.Metrics {
			if cited[m.ID] && m.Name == "lock_waiting_sessions" && m.Incident != nil && *m.Incident > 0 {
				waiting = true
			}
		}
		if !citedLock && !waiting {
			return "category lock_contention needs a cited blocker (L*) or a cited lock_waiting_sessions metric above zero"
		}
	case "deadlock":
		if !finding("deadlock") && !grew("deadlocks_per_second") {
			return "category deadlock contradicts the evidence: no deadlock incident and deadlocks_per_second did not grow"
		}
	case "temp_spill":
		if !finding("temp_file_growth") && !grew("temp_bytes_per_second") {
			return "category temp_spill contradicts the evidence: no temp_file_growth incident and temporary writes did not grow"
		}
	}
	return ""
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
