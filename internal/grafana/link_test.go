package grafana

import (
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestWindowURL(t *testing.T) {
	from := time.Date(2026, 11, 10, 15, 0, 0, 123000000, time.FixedZone("MSK", 3*60*60))
	to := from.Add(10 * time.Minute)
	for _, base := range []string{
		"http://localhost:3000/d/hunter/postgresql-investigation",
		"https://grafana.test/prefix/d/hunter?orgId=2&var-db=demo&var-db=other&timezone=Europe%2FMoscow&from=now-1h&from=now-2h&to=now&time=123&time.window=1000#panel",
	} {
		t.Run(base, func(t *testing.T) {
			link := WindowURL(base, from, to)
			u, err := url.Parse(link)
			if err != nil || link == "" {
				t.Fatal("missing dashboard link", link, err)
			}
			q := u.Query()
			if q.Get("from") != strconv.FormatInt(from.UnixMilli(), 10) || q.Get("to") != strconv.FormatInt(to.UnixMilli(), 10) || len(q["from"]) != 1 || len(q["to"]) != 1 {
				t.Fatal("incorrect absolute time range", q)
			}
			if q.Has("time") || q.Has("time.window") {
				t.Fatal("conflicting time selectors", q)
			}
			original, _ := url.Parse(base)
			if u.Scheme != original.Scheme || u.Host != original.Host || u.Path != original.Path || u.Fragment != original.Fragment {
				t.Fatal("dashboard location changed", u)
			}
			if original.Query().Has("orgId") && (q.Get("orgId") != "2" || q.Get("timezone") != "Europe/Moscow" || len(q["var-db"]) != 2) {
				t.Fatal("dashboard parameters lost", q)
			}
		})
	}
}

func TestWindowURLOmitsInvalidLinks(t *testing.T) {
	at := time.Now()
	for _, base := range []string{"", "/d/hunter", "ftp://grafana.test/d/hunter", "https://%", "https://grafana.test?orgId=%zz"} {
		if got := WindowURL(base, at, at); got != "" {
			t.Fatalf("accepted invalid dashboard URL %q: %q", base, got)
		}
	}
	if got := WindowURL("https://grafana.test", at, at.Add(-time.Second)); got != "" {
		t.Fatal("accepted reversed range", got)
	}
}
