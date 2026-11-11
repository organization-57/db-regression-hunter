package collector

import (
	"strings"
	"testing"
)

func TestCompactPlanScrubsConstantsAcrossLinesAndCaps(t *testing.T) {
	plan := compactPlan([]string{
		"Seq Scan on people  (cost=0.00..35.50 rows=10 width=4)",
		"  Filter: (note = 'line1",
		"secret passport 4510'::text)",
	})
	if strings.Contains(plan, "secret") || strings.Contains(plan, "4510") || !strings.Contains(plan, "Filter: (note = '…'::text)") {
		t.Fatalf("plan %q", plan)
	}
	var long []string
	for n := 0; n < 40; n++ {
		long = append(long, "  ->  Index Scan using orders_pkey on orders  (cost=0.29..8.31 rows=1 width=8)")
	}
	if capped := compactPlan(long); strings.Count(capped, "\n") > planLines || len(capped) > planChars+10 || !strings.HasSuffix(capped, "…") {
		t.Fatalf("plan is not capped: %d lines, %d bytes", strings.Count(capped, "\n"), len(capped))
	}
}
