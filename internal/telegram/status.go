package telegram

import (
	"fmt"
	"strings"
	"time"

	"github.com/makeev/db-regression-hunter/internal/state"
)

// StatusSummary formats the collected state without accessing the database or detector.
func StatusSummary(view state.View, pollInterval time.Duration, now time.Time) string {
	var message strings.Builder
	if view.Healthy && view.Latest != nil {
		message.WriteString("🟢 Мониторинг PostgreSQL\n")
		message.WriteString("Сбор: данные актуальны\n")
	} else {
		message.WriteString("🔴 Мониторинг PostgreSQL\n")
		message.WriteString("Сбор недоступен или данные устарели\n")
	}
	if view.Latest == nil {
		message.WriteString("Данных пока нет\n")
		fmt.Fprintf(&message, "Интервал опроса: %s\n", pollInterval)
	} else {
		snapshot := view.Latest
		age := now.Sub(snapshot.At)
		if age < 0 {
			age = 0
		}
		fmt.Fprintf(&message, "Последний снимок: %s\nДавность снимка: %s\nИнтервал опроса: %s\n\n", formatTime(snapshot.At), age.Round(time.Second), pollInterval)
		if !view.Healthy {
			message.WriteString("Последние известные данные\n")
		}
		fmt.Fprintf(&message, "Активных сессий: %d\nЗависших на блокировках транзакций: %d\nВозраст самого старого активного запроса: %.2f с\n", snapshot.Active, snapshot.LockWaiters, snapshot.OldestQuerySeconds)
	}
	fmt.Fprintf(&message, "\nСохранено расследований: %d\n", len(view.Incidents))
	if len(view.Incidents) == 0 {
		message.WriteString("Расследований пока нет")
	} else {
		fmt.Fprintf(&message, "Последнее: /incident %s", view.Incidents[len(view.Incidents)-1].ID)
	}
	return message.String()
}
