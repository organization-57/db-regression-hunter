// Package grafana builds dashboard links without contacting Grafana.
package grafana

import (
	"net/url"
	"strconv"
	"time"
)

// WindowURL preserves dashboard parameters and selects an absolute time range.
// An empty or invalid dashboard URL produces no link.
func WindowURL(dashboardURL string, from, to time.Time) string {
	u, err := url.Parse(dashboardURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || from.After(to) {
		return ""
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return ""
	}
	// Remove the alternative Grafana time-window selector to avoid ambiguity.
	query.Del("time")
	query.Del("time.window")
	query.Set("from", strconv.FormatInt(from.UnixMilli(), 10))
	query.Set("to", strconv.FormatInt(to.UnixMilli(), 10))
	u.RawQuery = query.Encode()
	return u.String()
}
