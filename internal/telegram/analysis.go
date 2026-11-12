package telegram

import (
	"fmt"
	"html"
	"math"
	"strings"

	"github.com/makeev/db-regression-hunter/internal/analysis"
	"github.com/makeev/db-regression-hunter/internal/evidence"
)

const (
	messageBudget   = 4000
	cardActions     = 2
	titleCap        = 200
	explanationCap  = 440
	actionCap       = 240
	sqlCap          = 400
	noteCap         = 200
	pendingAnalysis = "Анализ причины выполняется."
)

var categoryNames = map[string]string{
	"lock_contention": "конкуренция за блокировки", "long_transaction": "долгая транзакция", "blocking_ddl": "блокирующий DDL",
	"deadlock": "deadlock", "slow_query": "медленный запрос", "plan_regression": "смена плана запроса",
	"missing_index": "нет нужного индекса", "temp_spill": "сброс сортировок на диск", "connection_saturation": "всплеск сессий",
	"io_cache_miss": "промахи буферного кеша", "load_growth": "рост нагрузки", "unknown": "не установлена",
}

var metricNames = map[string]string{
	"oldest_query_seconds": "возраст самого старого активного запроса, с",
	"deadlocks_delta":      "deadlock за интервал", "sql_mean_exec_ms": "среднее время выполнения SQL, мс/вызов",
	"oldest_active_query_age": "возраст самого старого запроса, с", "active_sessions": "активные сессии", "lock_waiting_sessions": "ожидают блокировку",
	"commits_per_second": "коммиты в секунду", "rollbacks_per_second": "откаты в секунду", "deadlocks_per_second": "deadlock в секунду",
	"blocks_read_per_second": "чтения блоков в секунду", "temp_bytes_per_second": "временные файлы, байт/с", "cache_hit_ratio": "попадания в кеш, %",
}

var reasonNames = map[string]string{
	"timeout": "модель не ответила за отведённое время", "invalid_answer": "ответы модели не прошли проверку",
	"unavailable": "модель недоступна", "invalid_evidence": "данные не удалось подготовить для модели",
}

type markup struct {
	b     strings.Builder
	width int
}

func (m *markup) text(s string) *markup {
	m.b.WriteString(html.EscapeString(s))
	m.width += units(s)
	return m
}

func (m *markup) tag(name, s string) *markup {
	m.b.WriteString("<" + name + ">")
	m.text(s)
	m.b.WriteString("</" + name + ">")
	return m
}

func (m *markup) append(o *markup) *markup {
	m.b.WriteString(o.b.String())
	m.width += o.width
	return m
}

func units(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r > 0xffff {
			n++
		}
	}
	return n
}

func FormatAnalysis(r analysis.Result) string {
	card := analysisCard(r, messageBudget)
	if card == nil {
		return html.EscapeString(pendingAnalysis)
	}
	if details := analysisDetails(r, messageBudget-card.width-1); details != nil {
		card.text("\n")
		card.b.WriteString("<blockquote expandable>")
		card.append(details)
		card.b.WriteString("</blockquote>")
	}
	return card.b.String()
}

func AnalysisCard(r analysis.Result, budget int) string {
	card := analysisCard(r, budget)
	if card == nil {
		return html.EscapeString(pendingAnalysis)
	}
	return card.b.String()
}

func analysisCard(r analysis.Result, budget int) *markup {
	a := r.Analysis
	if r.Status == analysis.Pending || a == nil {
		return nil
	}
	head := &markup{}
	if r.Status == analysis.Fallback {
		reason := reasonNames[r.Reason]
		if reason == "" {
			reason = r.Reason
		}
		head.tag("b", "Предварительно, без LLM:").text(" " + reason + "\n")
	}
	title, why := a.Summary, ""
	if len(a.RootCauses) > 0 {
		c := a.RootCauses[0]
		title = LimitText(c.Title, titleCap) + " · уверенность " + confidence(c.Confidence)
		why = c.Explanation
	}
	head.tag("b", "Причина:").text(" " + LimitText(title, titleCap+30))
	if why != "" {
		room := budget - head.width - units("\nПочему: ")
		head.text("\n").tag("b", "Почему:").text(" " + LimitText(why, max(1, min(explanationCap, room))))
	}
	var actions []*markup
	for n, rec := range a.Recommendations {
		if n == cardActions {
			break
		}
		actions = append(actions, action(n+1, rec))
	}
	if len(actions) == 0 {
		return head
	}
	header := (&markup{}).text("\n\n").tag("b", "Что сделать")
	if head.width+header.width+actions[0].width > budget {
		actions[0] = action(1, analysis.Recommendation{Action: a.Recommendations[0].Action, RequiresApproval: a.Recommendations[0].RequiresApproval})
		if head.width+header.width+actions[0].width > budget {
			return head
		}
	}
	head.append(header)
	for _, line := range actions {
		if head.width+line.width > budget {
			break
		}
		head.append(line)
	}
	return head
}

func action(n int, rec analysis.Recommendation) *markup {
	m := (&markup{}).text(fmt.Sprintf("\n%d. %s", n, LimitText(rec.Action, actionCap)))
	if rec.RequiresApproval {
		m.text(" · нужно подтверждение")
	}
	if rec.SQL != "" {
		m.text("\n").tag("code", LimitText(rec.SQL, sqlCap))
	}
	return m
}

func analysisDetails(r analysis.Result, budget int) *markup {
	a := r.Analysis
	var sections []*markup
	section := func(title string, lines []*markup) {
		if len(lines) == 0 {
			return
		}
		s := (&markup{}).text("\n").tag("b", title)
		for _, line := range lines {
			s.append(line)
		}
		sections = append(sections, s)
	}
	var facts []*markup
	if len(a.RootCauses) > 0 {
		for _, f := range factLines(r.Evidence, a.RootCauses[0].Evidence) {
			facts = append(facts, (&markup{}).text("\n• "+f))
		}
	}
	section("Данные", facts)
	var more []*markup
	for n := cardActions; n < len(a.Recommendations); n++ {
		more = append(more, action(n+1, a.Recommendations[n]))
	}
	section("Ещё действия", more)
	var checks []*markup
	for _, c := range a.Checks {
		m := (&markup{}).text("\n• " + LimitText(c.Step, noteCap))
		if c.SQL != "" {
			m.text("\n").tag("code", LimitText(c.SQL, sqlCap))
		}
		checks = append(checks, m)
	}
	section("Проверить", checks)
	var others []*markup
	for _, c := range a.RootCauses[min(1, len(a.RootCauses)):] {
		others = append(others, (&markup{}).text("\n• "+LimitText(c.Title, titleCap)+" · уверенность "+confidence(c.Confidence)))
	}
	section("Другие версии", others)
	section("Предположения", notes(a.Assumptions))
	section("Не хватает данных", notes(a.MissingData))
	footer := (&markup{}).text("\n" + footerText(r))
	out := (&markup{}).tag("b", "Подробнее")
	if out.width+footer.width > budget {
		return nil
	}
	for _, s := range sections {
		if out.width+s.width+footer.width <= budget {
			out.append(s)
		}
	}
	return out.append(footer)
}

func notes(items []string) []*markup {
	var lines []*markup
	for _, item := range items {
		lines = append(lines, (&markup{}).text("\n• "+LimitText(item, noteCap)))
	}
	return lines
}

func footerText(r analysis.Result) string {
	category := ""
	if a := r.Analysis; a != nil && len(a.RootCauses) > 0 {
		category = categoryNames[a.RootCauses[0].Category]
		if category == "" {
			category = a.RootCauses[0].Category
		}
		category = "Категория: " + category + " · "
	}
	source := "модель " + shortModel(r.Model)
	if r.Status == analysis.Fallback || r.Model == "" {
		source = "правила hunter без LLM"
	}
	return category + source + " · SQL не выполняется автоматически"
}

func factLines(p *evidence.Package, ids []string) []string {
	if p == nil {
		return nil
	}
	cited := map[string]bool{}
	for _, id := range ids {
		cited[id] = true
	}
	var lines []string
	for _, l := range p.Locks {
		if cited[l.ID] {
			lines = append(lines, fmt.Sprintf("PID %d (%s, %s, транзакция %g с) блокирует %d%s", l.BlockingPID, l.BlockingApplication, sessionStateName(l.BlockingState), l.TransactionAgeSeconds, l.BlockedTotal, query(l.BlockingQuery)))
		}
	}
	lines = append(lines, sessionLines(p.Sessions, cited)...)
	for _, s := range p.Statements {
		if cited[s.ID] {
			lines = append(lines, fmt.Sprintf("queryid %s: %s → %s мс на вызов, вызовов в секунду %s → %s%s", s.QueryID, number(s.MeanExecMS.Baseline), number(s.MeanExecMS.Incident),
				number(s.CallsPerSecond.Baseline), number(s.CallsPerSecond.Incident), query(s.Query)))
		}
	}
	for _, t := range p.Tables {
		if cited[t.ID] {
			lines = append(lines, fmt.Sprintf("таблица %s: около %g строк, %g МБ, мёртвых строк %s", t.QualifiedName(), t.EstimatedRows, math.Round(t.TotalBytes/1e5)/10, number(t.DeadTuples)))
		}
	}
	for _, m := range p.Metrics {
		if cited[m.ID] {
			lines = append(lines, fmt.Sprintf("%s: %s → %s", metricName(m.Name), number(m.Baseline), number(m.Incident)))
		}
	}
	return lines
}

func sessionLines(sessions []evidence.Session, cited map[string]bool) []string {
	type group struct {
		app, wait string
		pids      []string
		age       float64
	}
	var groups []*group
	byKey := map[string]*group{}
	for _, s := range sessions {
		if !cited[s.ID] {
			continue
		}
		wait := s.WaitEvent
		if wait == "" {
			wait = sessionStateName(s.State)
		}
		key := s.Application + "\x00" + wait
		g := byKey[key]
		if g == nil {
			g = &group{app: s.Application, wait: wait}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.pids = append(g.pids, fmt.Sprint(s.PID))
		g.age = max(g.age, s.QueryAgeSeconds)
	}
	var lines []string
	for _, g := range groups {
		if len(g.pids) == 1 {
			lines = append(lines, fmt.Sprintf("PID %s (%s, %s) выполняется %g с", g.pids[0], g.app, g.wait, g.age))
			continue
		}
		lines = append(lines, fmt.Sprintf("%d %s %s, %s, до %g с: PID %s", len(g.pids), sessionsWord(len(g.pids)), g.app, g.wait, g.age, strings.Join(g.pids, ", ")))
	}
	return lines
}

func sessionsWord(n int) string {
	switch {
	case n%10 == 1 && n%100 != 11:
		return "сессия"
	case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
		return "сессии"
	}
	return "сессий"
}

func query(q string) string {
	if q == "" {
		return ""
	}
	return "; запрос: " + LimitText(q, 100)
}

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
	if math.Abs(*v) >= 1000 {
		return fmt.Sprintf("%.0f", *v)
	}
	return fmt.Sprintf("%.3g", *v)
}

func shortModel(m string) string {
	if i := strings.LastIndex(m, "/"); i >= 0 {
		return m[i+1:]
	}
	return m
}
