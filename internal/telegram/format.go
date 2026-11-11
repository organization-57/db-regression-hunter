package telegram

import "time"

var moscow = time.FixedZone("MSK", 3*60*60)

func formatTime(at time.Time) string {
	return at.In(moscow).Format("02.01.2006 15:04:05") + " МСК"
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
