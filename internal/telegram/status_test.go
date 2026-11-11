package telegram

import (
	"strings"
	"testing"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/detector"
	"github.com/makeev/db-regression-hunter/internal/state"
)

func TestStatusSummaryFreshSnapshot(t *testing.T) {
	at := time.Date(2026, 11, 10, 15, 0, 0, 0, time.UTC)
	view := state.View{
		Healthy:   true,
		Latest:    &collector.Snapshot{At: at, Active: 3, LockWaiters: 1, OldestQuerySeconds: 2.4},
		Incidents: []detector.Incident{{ID: "older"}, {ID: "1794321188121986000"}},
	}
	want := `🟢 Мониторинг PostgreSQL
Сбор: данные актуальны
Последний снимок: 10.11.2026 18:00:00 МСК
Давность снимка: 5s
Интервал опроса: 10s

Активных сессий: 3
Ожидают блокировку Lock: 1
Возраст самого старого активного запроса: 2.40 с

Сохранено расследований: 2
Последнее: /incident 1794321188121986000`
	if got := StatusSummary(view, 10*time.Second, at.Add(5*time.Second)); got != want {
		t.Fatalf("unexpected summary:\n%s\nwant:\n%s", got, want)
	}
}

func TestStatusSummaryUnavailableCollection(t *testing.T) {
	at := time.Now().Add(-time.Second)
	for _, failure := range []bool{false, true} {
		name := "stale"
		if failure {
			name = "failed with fresh snapshot"
		}
		t.Run(name, func(t *testing.T) {
			store := &state.Store{}
			store.Update(collector.Snapshot{At: at, Active: 7, LockWaiters: 2, OldestQuerySeconds: 12.345}, nil)
			maxAge := time.Nanosecond
			if failure {
				maxAge = 100 * 365 * 24 * time.Hour
				store.Failed(nil)
			}
			got := StatusSummary(store.View(maxAge, true), 10*time.Second, at.Add(time.Minute))
			if !strings.HasPrefix(got, "🔴 Мониторинг PostgreSQL\n") {
				t.Fatal("missing stale indicator", got)
			}
			for _, part := range []string{"Сбор недоступен или данные устарели", "Последние известные данные", "Давность снимка: 1m0s", "Активных сессий: 7", "Ожидают блокировку Lock: 2", "12.35 с", "Сохранено расследований: 0", "Расследований пока нет"} {
				if !strings.Contains(got, part) {
					t.Fatalf("missing %q in %s", part, got)
				}
			}
			if strings.Contains(got, "данные актуальны") {
				t.Fatal("unavailable collection reported as fresh", got)
			}
		})
	}
}

func TestStatusSummaryBeforeFirstSnapshot(t *testing.T) {
	want := "🔴 Мониторинг PostgreSQL\nСбор недоступен или данные устарели\nДанных пока нет\nИнтервал опроса: 10s\n\nСохранено расследований: 0\nРасследований пока нет"
	if got := StatusSummary(state.View{}, 10*time.Second, time.Now()); got != want {
		t.Fatalf("unknown metrics must not be displayed as zero:\n%s", got)
	}
}

func TestStatusSummarySnapshotAge(t *testing.T) {
	at := time.Date(2026, 11, 10, 15, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		elapsed time.Duration
		want    string
	}{
		{"round down", 1400 * time.Millisecond, "1s"},
		{"round up", 1600 * time.Millisecond, "2s"},
		{"future snapshot", -time.Second, "0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := StatusSummary(state.View{Healthy: true, Latest: &collector.Snapshot{At: at}}, 10*time.Second, at.Add(tc.elapsed))
			if !strings.Contains(got, "Давность снимка: "+tc.want+"\n") {
				t.Fatal("incorrect snapshot age", got)
			}
		})
	}
}
