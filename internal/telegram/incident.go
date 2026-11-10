package telegram

import (
	"time"

	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/grafana"
)

const incidentWindowPadding = 5 * time.Minute

// IncidentSummary formats any incident, independently of how it was selected.
func (b *Bot) IncidentSummary(i detector.Incident) string {
	message := FormatIncident(i)
	link := grafana.WindowURL(b.grafanaURL, i.StartedAt.Add(-incidentWindowPadding), i.DetectedAt.Add(incidentWindowPadding))
	if link != "" {
		message += "\n\nGrafana: " + link
	}
	return message
}
