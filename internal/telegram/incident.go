package telegram

import (
	"html"
	"net/url"
	"strings"
	"time"

	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/grafana"
)

const incidentWindowPadding = 5 * time.Minute

// IncidentSummary returns Telegram HTML, independently of how the incident was selected.
func (b *Bot) IncidentSummary(i detector.Incident) string {
	message := html.EscapeString(FormatIncident(i))
	link := grafana.WindowURL(b.grafanaURL, i.StartedAt.Add(-incidentWindowPadding), i.StartedAt.Add(incidentWindowPadding))
	if link != "" {
		u, _ := url.Parse(link)
		if strings.EqualFold(u.Hostname(), "localhost") {
			port := u.Port()
			u.Host = "127.0.0.1"
			if port != "" {
				u.Host += ":" + port
			}
			link = u.String()
		}
		message += "\n\n📊 <a href=\"" + html.EscapeString(link) + "\">Ссылка на окно в Grafana</a>"
	}
	return message
}
