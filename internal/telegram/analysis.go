package telegram

import (
	"fmt"
	"strings"

	"github.com/makeev/db-regression-hunter/internal/analysis"
	"github.com/makeev/db-regression-hunter/internal/evidence"
)

var categoryNames = map[string]string{
	"lock_contention": "конкуренция за блокировки", "long_transaction": "долгая транзакция", "blocking_ddl": "блокирующий DDL",
	"deadlock": "взаимные блокировки", "slow_query": "медленный запрос", "plan_regression": "смена плана запроса",
	"missing_index": "нет нужного индекса", "temp_spill": "сброс сортировок на диск", "connection_saturation": "всплеск сессий",
	"io_cache_miss": "промахи буферного кеша", "load_growth": "рост нагрузки", "unknown": "не установлена",
}

var findingNames = map[string]string{
	"query_age_regression": "долгие запросы", "lock_wait": "ожидания блокировок", "lock_contention": "блокировки",
	"active_sessions_surge": "всплеск сессий", "temp_file_growth": "временные файлы", "deadlock": "deadlock",
	"sql_execution_regression": "замедление SQL",
}

var metricNames = map[string]string{
	"oldest_active_query_age": "возраст самого старого запроса, с", "active_sessions": "активные сессии", "lock_waiting_sessions": "ожидают блокировку",
	"commits_per_second": "коммиты в секунду", "rollbacks_per_second": "откаты в секунду", "deadlocks_per_second": "deadlock в секунду",
	"blocks_read_per_second": "чтения блоков в секунду", "temp_bytes_per_second": "временные файлы, байт/с", "cache_hit_ratio": "попадания в кеш, %",
}

var priorityNames = map[string]string{"now": "сейчас", "next": "далее", "later": "позже"}

func confidence(c float64) string {
	switch {
	case c >= 0.75:
		return "высокая"
	case c >= 0.45:
		return "средняя"
	}
	return "низкая"
}

func number(v *float64) string {
	if v == nil {
		return "?"
	}
	return fmt.Sprintf("%g", *v)
}

func fact(p *evidence.Package, id string) string {
	if p == nil {
		return ""
	}
	for _, i := range p.Incidents {
		if i.ID == id {
			return fmt.Sprintf("сигнал %s: %g при пороге %g", i.Finding, i.Peak, i.Threshold)
		}
	}
	for _, m := range p.Metrics {
		if m.ID == id {
			name := metricNames[m.Name]
			if name == "" {
				name = m.Name
			}
			return fmt.Sprintf("%s: %s → %s", name, number(m.Baseline), number(m.Incident))
		}
	}
	for _, l := range p.Locks {
		if l.ID == id {
			return fmt.Sprintf("PID %d (%s, %s, транзакция %g с) блокирует %d", l.BlockingPID, l.BlockingApplication, l.BlockingState, l.TransactionAgeSeconds, l.BlockedTotal)
		}
	}
	for _, s := range p.Sessions {
		if s.ID == id {
			return fmt.Sprintf("PID %d (%s, %s) выполняется %g с", s.PID, s.Application, s.WaitEvent, s.QueryAgeSeconds)
		}
	}
	for _, s := range p.Statements {
		if s.ID == id {
			return fmt.Sprintf("queryid %s: %s → %s мс на вызов, вызовов в секунду %s → %s", s.QueryID, number(s.MeanExecMS.Baseline), number(s.MeanExecMS.Incident),
				number(s.CallsPerSecond.Baseline), number(s.CallsPerSecond.Incident))
		}
	}
	return ""
}

func FormatAnalysis(r analysis.Result) string {
	a := r.Analysis
	if a == nil {
		return ""
	}
	var signals []string
	if r.Evidence != nil {
		for _, i := range r.Evidence.Incidents {
			name := findingNames[i.Finding]
			if name == "" {
				name = i.Finding
			}
			signals = append(signals, name)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Анализ Gonka · сигналы: %s\n\n%s\n", strings.Join(signals, ", "), a.Summary)
	if len(a.RootCauses) > 0 {
		c := a.RootCauses[0]
		name := categoryNames[c.Category]
		if name == "" {
			name = c.Category
		}
		fmt.Fprintf(&b, "Причина: %s — %s (уверенность %s)\n%s\n", c.Title, name, confidence(c.Confidence), c.Explanation)
		var facts []string
		for _, id := range c.Evidence {
			if f := fact(r.Evidence, id); f != "" {
				facts = append(facts, "• "+f)
			}
		}
		if len(facts) > 0 {
			b.WriteString("\nПочему так думаем:\n" + strings.Join(facts, "\n") + "\n")
		}
		for _, other := range a.RootCauses[1:] {
			fmt.Fprintf(&b, "Также возможно: %s (уверенность %s)\n", other.Title, confidence(other.Confidence))
		}
	}
	if len(a.Recommendations) > 0 {
		b.WriteString("\nЧто сделать:\n")
		for n, rec := range a.Recommendations {
			approval := ""
			if rec.RequiresApproval {
				approval = ", нужно подтверждение"
			}
			fmt.Fprintf(&b, "%d. [%s%s] %s\n", n+1, priorityNames[rec.Priority], approval, rec.Action)
			if rec.SQL != "" {
				fmt.Fprintf(&b, "   %s\n", rec.SQL)
			}
			fmt.Fprintf(&b, "   Проверка: %s\n", rec.Verify)
		}
	}
	if len(a.Checks) > 0 {
		b.WriteString("\nКак проверить:\n")
		for n, c := range a.Checks {
			fmt.Fprintf(&b, "%d. %s\n", n+1, c.Step)
			if c.SQL != "" {
				fmt.Fprintf(&b, "   %s\n", c.SQL)
			}
		}
	}
	if len(a.Assumptions) > 0 {
		b.WriteString("\nПредположения, не подтверждённые данными: " + strings.Join(a.Assumptions, "; ") + "\n")
	}
	if len(a.MissingData) > 0 {
		b.WriteString("Не хватает данных: " + strings.Join(a.MissingData, "; ") + "\n")
	}
	fmt.Fprintf(&b, "\nGonka %s · %.0f с · модель только объясняет, SQL не выполняется автоматически.", shortModel(r.Model), float64(r.LatencyMs)/1000)
	text := []rune(b.String())
	if len(text) > 3500 {
		return string(text[:3490]) + "…"
	}
	return string(text)
}

func shortModel(m string) string {
	if i := strings.LastIndex(m, "/"); i >= 0 {
		return m[i+1:]
	}
	return m
}
