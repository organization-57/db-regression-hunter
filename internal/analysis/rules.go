package analysis

import (
	"fmt"
	"strings"

	"github.com/makeev/db-regression-hunter/internal/evidence"
)

type rules struct {
	p       evidence.Package
	metrics map[string]evidence.Metric
}

func Rules(p evidence.Package) Analysis {
	r := rules{p: p, metrics: map[string]evidence.Metric{}}
	for _, m := range p.Metrics {
		r.metrics[m.Name] = m
	}
	a := r.explain()
	a.Assumptions = append(a.Assumptions, "вывод сделан правилами hunter без LLM по тем же доказательствам; уверенность ниже, чем у проверенного ответа модели")
	a.MissingData = append(a.MissingData, "объяснение модели: анализ Gonka не получен")
	return a
}

func (r rules) explain() Analysis {
	if i, ok := r.incident("deadlock"); ok {
		return r.single(Cause{Category: "deadlock", Title: "Взаимные блокировки транзакций", Confidence: 0.6, Evidence: r.cite(i.ID, r.id("deadlocks_per_second")),
			Explanation: "PostgreSQL обнаруживает deadlock и откатывает одну из транзакций."},
			Recommendation{Action: "Захватывать строки в транзакциях в одном порядке, например по возрастанию ключа", Priority: "next", Risk: "low", Verify: r.verify("deadlocks_per_second", "0")},
			Check{Step: "Найти в журнале PostgreSQL сообщения deadlock detected и запросы-участники", Expect: "две транзакции обновляют одни строки в разном порядке"})
	}
	if l, ok := r.rootLock(); ok {
		return r.lock(l)
	}
	if i, ok := r.incident("temp_file_growth"); ok {
		return r.single(Cause{Category: "temp_spill", Title: "Сортировки и хеши уходят во временные файлы", Confidence: 0.6, Evidence: r.cite(i.ID, r.id("temp_bytes_per_second")),
			Explanation: "Скорость записи временных файлов выросла относительно baseline."},
			Recommendation{Action: "Найти запросы с наибольшим temp_blks_written и добавить индекс под сортировку или поднять work_mem для них", Priority: "next", Risk: "low", Verify: r.verify("temp_bytes_per_second", r.baseline("temp_bytes_per_second"))},
			Check{Step: "Найти запросы, пишущие временные файлы", SQL: "SELECT queryid, calls, temp_blks_written FROM pg_stat_statements ORDER BY temp_blks_written DESC LIMIT 5", Expect: "один или два queryid дают основную запись"})
	}
	if i, ok := r.incident("active_sessions_surge"); ok {
		if r.grew("commits_per_second", 1.5) {
			return r.single(Cause{Category: "load_growth", Title: "Рост клиентской нагрузки", Confidence: 0.5, Evidence: r.cite(i.ID, r.id("commits_per_second"), r.id("active_sessions")),
				Explanation: "Сессий стало больше вместе с числом коммитов: база обслуживает больше запросов."},
				Recommendation{Action: "Проверить источник роста трафика и запас по пулу соединений", Priority: "next", Risk: "low", Verify: r.verify("active_sessions", r.baseline("active_sessions"))},
				Check{Step: "Сравнить число сессий по приложениям", SQL: "SELECT application_name, state, count(*) FROM pg_stat_activity GROUP BY 1, 2 ORDER BY 3 DESC", Expect: "рост у клиентского приложения"})
		}
		return r.single(Cause{Category: "connection_saturation", Title: "Лишние одновременные сессии", Confidence: 0.5, Evidence: r.cite(i.ID, r.id("active_sessions"), r.session()),
			Explanation: "Активных сессий стало больше, а число коммитов не выросло: базу заняли долгие задачи."},
			Recommendation{Action: "Найти источник дополнительных сессий и ограничить его параллелизм", Priority: "next", Risk: "low", Verify: r.verify("active_sessions", r.baseline("active_sessions"))},
			Check{Step: "Сравнить число сессий по приложениям", SQL: "SELECT application_name, state, count(*) FROM pg_stat_activity GROUP BY 1, 2 ORDER BY 3 DESC", Expect: "много активных сессий одного приложения"})
	}
	if i, ok := r.incident("query_age_regression"); ok && len(r.p.Sessions) > 0 {
		s := r.p.Sessions[0]
		return r.single(Cause{Category: "slow_query", Title: fmt.Sprintf("Долгий запрос PID %d", s.PID), Confidence: 0.5, Evidence: r.cite(i.ID, s.ID),
			Explanation: fmt.Sprintf("Блокировок нет, а запрос PID %d выполняется %g с.", s.PID, s.QueryAgeSeconds)},
			Recommendation{Action: fmt.Sprintf("Проверить план и необходимость запроса PID %d; при необходимости отменить его после согласования", s.PID), Priority: "next", Risk: "low", Verify: r.verify("oldest_active_query_age", r.baseline("oldest_active_query_age"))},
			Check{Step: fmt.Sprintf("Посмотреть, что выполняет PID %d", s.PID), SQL: fmt.Sprintf("SELECT pid, state, wait_event_type, wait_event, now() - query_start AS running FROM pg_stat_activity WHERE pid = %d", s.PID), Expect: "один долгий запрос без ожидания блокировок"})
	}
	if len(r.p.Statements) > 0 {
		return r.statement(r.p.Statements[0])
	}
	first := ""
	if len(r.p.Incidents) > 0 {
		first = r.p.Incidents[0].ID
	}
	return r.single(Cause{Category: "unknown", Title: "Причина не установлена", Confidence: 0.2, Evidence: r.cite(first),
		Explanation: "Правила не нашли блокировок, deadlock, временных файлов, долгих сессий или регрессий SQL, объясняющих сигнал."},
		Recommendation{Action: "Посмотреть графики Grafana за окно инцидента и журнал PostgreSQL", Priority: "next", Risk: "low", Verify: "сигнал инцидента вернётся ниже порога"},
		Check{Step: "Сопоставить сигнал с деплоями и изменениями конфигурации", Expect: "событие незадолго до начала инцидента"})
}

func (r rules) lock(l evidence.Lock) Analysis {
	c := Cause{Category: "lock_contention", Title: fmt.Sprintf("Блокировки вокруг PID %d", l.BlockingPID), Confidence: 0.5, Evidence: r.cite(l.ID, r.id("lock_waiting_sessions")),
		Explanation: fmt.Sprintf("PID %d (%s, %s) блокирует %d сессий.", l.BlockingPID, l.BlockingApplication, l.BlockingState, l.BlockedTotal)}
	switch {
	case contains(l.WaiterWaitEvents, "Lock:relation"):
		c.Category, c.Title, c.Confidence = "blocking_ddl", fmt.Sprintf("Табличная блокировка от PID %d", l.BlockingPID), 0.6
		c.Explanation = fmt.Sprintf("Ожидающие ждут Lock:relation, то есть блокировку всей таблицы; PID %d (%s) блокирует %d сессий.", l.BlockingPID, l.BlockingApplication, l.BlockedTotal)
	case strings.HasPrefix(l.BlockingState, "idle in transaction"):
		c.Category, c.Title, c.Confidence = "long_transaction", fmt.Sprintf("Незавершённая транзакция PID %d", l.BlockingPID), 0.6
		c.Explanation = fmt.Sprintf("PID %d в состоянии %s %g с держит блокировки строк, за ним ждут %d сессий.", l.BlockingPID, l.BlockingState, l.TransactionAgeSeconds, l.BlockedTotal)
	}
	rec := Recommendation{Action: "Найти в приложении транзакцию, которая держит блокировку, и закрыть её", Priority: "now", Risk: "low", Verify: r.verify("lock_waiting_sessions", "0"), Evidence: r.cite(l.ID)}
	if r.p.RootPIDs()[fmt.Sprint(l.BlockingPID)] {
		rec = Recommendation{Action: fmt.Sprintf("Завершить корневой блокировщик PID %d, если транзакцию нельзя закрыть из приложения", l.BlockingPID), Priority: "now", Risk: "medium",
			SQL: fmt.Sprintf("SELECT pg_terminate_backend(%d)", l.BlockingPID), Verify: r.verify("lock_waiting_sessions", "0"), Evidence: r.cite(l.ID), RequiresApproval: true}
	}
	a := r.single(c, rec, Check{Step: fmt.Sprintf("Проверить, что PID %d всё ещё держит блокировку", l.BlockingPID),
		SQL: fmt.Sprintf("SELECT pid, state, wait_event_type, now() - xact_start AS transaction_age FROM pg_stat_activity WHERE pid = %d", l.BlockingPID), Expect: "транзакция всё ещё открыта"})
	a.Summary = fmt.Sprintf("%s: за ним ждут %d сессий.", c.Title, l.BlockedTotal)
	return a
}

func (r rules) statement(s evidence.Statement) Analysis {
	c := Cause{Category: "slow_query", Title: fmt.Sprintf("Замедлился запрос queryid %s", s.QueryID), Confidence: 0.4, Evidence: r.cite(s.ID),
		Explanation: "Среднее время выполнения выросло без блокировок и других сигналов."}
	switch {
	case s.LoadIncreased:
		c.Category, c.Explanation = "load_growth", "Запрос вызывается чаще, чем в baseline."
	case s.SharedReadsPerCall.Baseline != nil && s.SharedReadsPerCall.Incident != nil && *s.SharedReadsPerCall.Incident > 1.5**s.SharedReadsPerCall.Baseline:
		c.Category, c.Explanation = "plan_regression", "Чтений на вызов стало больше при той же частоте: похоже на смену плана или пропавший индекс."
	}
	return r.single(c,
		Recommendation{Action: fmt.Sprintf("Сравнить текущий план queryid %s с прежним и проверить индексы", s.QueryID), Priority: "next", Risk: "low",
			Verify: fmt.Sprintf("%s: среднее время вернётся к %s мс", s.ID, number(s.MeanExecMS.Baseline)), Evidence: r.cite(s.ID)},
		Check{Step: "Посмотреть статистику запроса", SQL: fmt.Sprintf("SELECT queryid, calls, mean_exec_time, shared_blks_read FROM pg_stat_statements WHERE queryid = %s", s.QueryID), Expect: "рост mean_exec_time и чтений"})
}

func (r rules) single(c Cause, rec Recommendation, check Check) Analysis {
	return Analysis{Summary: c.Title + ". " + c.Explanation, RootCauses: []Cause{c}, Checks: []Check{check}, Recommendations: []Recommendation{rec}}
}

func (r rules) incident(finding string) (evidence.Incident, bool) {
	for _, i := range r.p.Incidents {
		if i.Finding == finding {
			return i, true
		}
	}
	return evidence.Incident{}, false
}

func (r rules) rootLock() (evidence.Lock, bool) {
	for _, l := range r.p.Locks {
		if l.Root {
			return l, true
		}
	}
	return evidence.Lock{}, false
}

func (r rules) session() string {
	if len(r.p.Sessions) > 0 {
		return r.p.Sessions[0].ID
	}
	return ""
}

func (r rules) id(metric string) string { return r.metrics[metric].ID }

func (r rules) baseline(metric string) string { return number(r.metrics[metric].Baseline) }

func (r rules) grew(metric string, factor float64) bool {
	m := r.metrics[metric]
	return m.Baseline != nil && m.Incident != nil && *m.Incident > factor**m.Baseline
}

func (r rules) verify(metric, level string) string {
	if id := r.id(metric); id != "" {
		return fmt.Sprintf("%s (%s) вернётся к %s", id, metric, level)
	}
	return fmt.Sprintf("%s вернётся к %s", metric, level)
}

func (r rules) cite(ids ...string) []string {
	var out []string
	for _, id := range ids {
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

func number(v *float64) string {
	if v == nil {
		return "baseline"
	}
	return fmt.Sprintf("%g", *v)
}
