package telegram

import "time"

var moscow = time.FixedZone("MSK", 3*60*60)

func formatTime(at time.Time) string {
	return at.In(moscow).Format("02.01.2006 15:04:05") + " МСК"
}

func metricName(metric string) string {
	if name, ok := metricNames[metric]; ok {
		return name
	}
	return metric
}

func sessionStateName(state string) string {
	switch state {
	case "active":
		return "выполняет запрос"
	case "idle":
		return "ожидает команду"
	case "idle in transaction":
		return "простой с открытой транзакцией"
	case "idle in transaction (aborted)":
		return "простой с открытой транзакцией после ошибки"
	default:
		return state
	}
}

// LimitText truncates plain text before HTML escaping, counting UTF-16 units
// so that emoji also fit within Telegram's message budget.
func LimitText(text string, maxUnits int) string {
	units := 0
	for index, r := range text {
		width := 1
		if r > 0xffff {
			width = 2
		}
		if units+width > maxUnits-1 {
			return text[:index] + "…"
		}
		units += width
	}
	return text
}
