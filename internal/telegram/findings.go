package telegram

var findingNames = map[string]string{
	"query_age_regression":     "долгие активные запросы",
	"lock_wait":                "ожидание блокировок",
	"lock_contention":          "найдены корневые блокировщики",
	"idle_in_transaction":      "простой с открытой транзакцией",
	"active_sessions_surge":    "всплеск активных сессий",
	"temp_file_growth":         "рост записи временных файлов",
	"deadlock":                 "deadlock",
	"sql_execution_regression": "замедление SQL",
}

func findingName(finding string) string {
	if name, ok := findingNames[finding]; ok {
		return name
	}
	return finding
}

func formatFindings(findings []string) []string {
	names := make([]string, len(findings))
	for n, finding := range findings {
		names[n] = findingName(finding)
	}
	return names
}
