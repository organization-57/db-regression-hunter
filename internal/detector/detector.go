package detector

import (
	"fmt"
	"math"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
)

type Incident struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"started_at"`
	DetectedAt time.Time `json:"detected_at"`
	Hypothesis string    `json:"hypothesis"`
	Evidence   []string  `json:"evidence"`
	NextSteps  []string  `json:"next_steps"`
}

// Detector is owned by the collection loop. Baseline is frozen during an anomaly.
type Detector struct {
	samples               []float64
	size, confirm, streak int
	factor                float64
	started               time.Time
	alerted               bool
}

func New(size, confirm int, factor float64) *Detector {
	return &Detector{size: size, confirm: confirm, factor: factor}
}

func (d *Detector) Reset() { d.samples = nil; d.streak = 0; d.alerted = false }

func (d *Detector) Observe(s collector.Snapshot) *Incident {
	if len(d.samples) < d.size {
		d.samples = append(d.samples, s.OldestQuerySeconds)
		return nil
	}
	var sum float64
	for _, v := range d.samples {
		sum += v
	}
	baseline := sum / float64(len(d.samples))
	threshold := math.Max(1, baseline*d.factor)
	if s.OldestQuerySeconds <= threshold {
		d.streak = 0
		d.alerted = false
		copy(d.samples, d.samples[1:])
		d.samples[len(d.samples)-1] = s.OldestQuerySeconds
		return nil
	}
	if d.streak == 0 {
		d.started = s.At
	}
	d.streak++
	if d.streak < d.confirm || d.alerted {
		return nil
	}
	d.alerted = true
	i := &Incident{ID: fmt.Sprintf("%d", s.At.UnixNano()), StartedAt: d.started, DetectedAt: s.At,
		Hypothesis: "Причина пока не установлена: вырос возраст активных запросов",
		Evidence:   []string{fmt.Sprintf("Самый старый активный запрос: %.2f s; baseline: %.2f s; порог: %.2f s; последовательных превышений: %d", s.OldestQuerySeconds, baseline, threshold, d.streak), fmt.Sprintf("Активных сессий: %d; ожидают Lock: %d", s.Active, s.LockWaiters)},
		NextSteps:  []string{"Проверить pg_stat_statements и изменения планов; сопоставить с latency API и временем деплоя"}}
	if s.LockWaiters > 0 {
		i.Hypothesis = "Блокировки — возможная причина деградации"
		i.NextSteps = []string{"Найти блокирующие PID через pg_blocking_pids(pid); проверить длительные транзакции", "После проверки владельцем приложения завершить или сократить блокирующую транзакцию; повторно измерить latency"}
	}
	return i
}
