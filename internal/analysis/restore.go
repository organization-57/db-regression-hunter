package analysis

import "github.com/makeev/db-regression-hunter/internal/redact"

// Restore only after validating the model's answer against anonymous evidence.
func restore(a *Analysis, names redact.Context) {
	a.Summary = names.Restore(a.Summary)
	for n := range a.RootCauses {
		c := &a.RootCauses[n]
		c.Title = names.Restore(c.Title)
		c.Explanation = names.Restore(c.Explanation)
	}
	for n := range a.Checks {
		c := &a.Checks[n]
		c.Step = names.Restore(c.Step)
		c.Expect = names.Restore(c.Expect)
		c.SQL = names.RestoreSQL(c.SQL)
	}
	for n := range a.Recommendations {
		r := &a.Recommendations[n]
		r.Action = names.Restore(r.Action)
		r.Verify = names.Restore(r.Verify)
		r.SQL = names.RestoreSQL(r.SQL)
	}
	for n := range a.Assumptions {
		a.Assumptions[n] = names.Restore(a.Assumptions[n])
	}
	for n := range a.MissingData {
		a.MissingData[n] = names.Restore(a.MissingData[n])
	}
}
