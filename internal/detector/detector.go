package detector

import (
	"fmt"
	"math"
	"time"

	"github.com/makeev/db-regression-hunter/internal/collector"
	"github.com/makeev/db-regression-hunter/internal/sqlstats"
)

const (
	Active   = "active"
	Resolved = "resolved"
	// Keep the first observation and the most recent observations of an episode.
	maxBlockingObservations = 20
)

type BlockingObservation struct {
	At                 time.Time               `json:"at"`
	OldestQuerySeconds float64                 `json:"oldest_query_seconds"`
	LockWaiters        int                     `json:"lock_waiters"`
	Graph              collector.BlockingGraph `json:"graph"`
}

type Incident struct {
	ID                     string                `json:"id"`
	StartedAt              time.Time             `json:"started_at"`
	DetectedAt             time.Time             `json:"detected_at"`
	UpdatedAt              time.Time             `json:"updated_at"`
	Status                 string                `json:"status"`
	Revision               int                   `json:"revision"`
	BaselineSeconds        float64               `json:"baseline_seconds"`
	ThresholdSeconds       float64               `json:"threshold_seconds"`
	Hypothesis             string                `json:"hypothesis"`
	Evidence               []string              `json:"evidence"`
	NextSteps              []string              `json:"next_steps"`
	Blocking               []BlockingObservation `json:"blocking"`
	BlockingSamplesDropped int                   `json:"blocking_samples_dropped"`
	CollectionGaps         int                   `json:"collection_gaps"`
	RecoverySamples        int                   `json:"recovery_samples"`
	RecoveryStartedAt      *time.Time            `json:"recovery_started_at,omitempty"`
	RecoveredAt            *time.Time            `json:"recovered_at,omitempty"`
	SQL                    sqlstats.Context      `json:"sql"`
}

// Clone prevents readers, queued notifications and later observations sharing slices.
func (i Incident) Clone() Incident {
	i.SQL = i.SQL.Clone()
	i.Evidence = append([]string(nil), i.Evidence...)
	i.NextSteps = append([]string(nil), i.NextSteps...)
	i.Blocking = append([]BlockingObservation(nil), i.Blocking...)
	for n := range i.Blocking {
		i.Blocking[n].Graph = i.Blocking[n].Graph.Clone()
	}
	if i.RecoveryStartedAt != nil {
		at := *i.RecoveryStartedAt
		i.RecoveryStartedAt = &at
	}
	if i.RecoveredAt != nil {
		at := *i.RecoveredAt
		i.RecoveredAt = &at
	}
	return i
}

// Detector belongs to the collection loop. Observe returns a new immutable
// revision of the episode, including updates and recovery, or nil when idle.
// Confirmation and recovery both require confirm successful observations.
type Detector struct {
	samples               []float64
	size, confirm, streak int
	factor                float64
	started, lastAt       time.Time
	pending               []BlockingObservation
	pendingDropped        int
	current               *Incident
	sqlHistory            []sqlstats.Report
	pendingSQL            sqlstats.Context
	// Zero disables gap checking for callers without a fixed polling interval.
	MaxSampleGap time.Duration
}

func New(size, confirm int, factor float64) *Detector {
	return &Detector{size: size, confirm: confirm, factor: factor}
}

func (d *Detector) Reset() {
	d.samples = nil
	d.streak = 0
	d.pending = nil
	d.pendingDropped = 0
	d.current = nil
	d.lastAt = time.Time{}
	d.sqlHistory = nil
	d.pendingSQL = sqlstats.Context{}
}

// CollectionFailed breaks consecutive confirmation/recovery. An open incident
// survives an outage: missing observations cannot prove recovery.
func (d *Detector) CollectionFailed() {
	d.streak = 0
	d.pending = nil
	d.pendingDropped = 0
	d.sqlHistory = nil
	d.pendingSQL = sqlstats.Context{}
	if d.current == nil {
		d.samples = nil
		return
	}
	d.current.CollectionGaps++
	d.current.RecoverySamples = 0
	d.current.RecoveryStartedAt = nil
}

func (d *Detector) Observe(s collector.Snapshot) *Incident {
	if !d.lastAt.IsZero() && !s.At.After(d.lastAt) {
		return nil
	}
	if d.MaxSampleGap > 0 && !d.lastAt.IsZero() && s.At.Sub(d.lastAt) > d.MaxSampleGap {
		d.CollectionFailed()
	}
	d.lastAt = s.At
	if d.current != nil {
		return d.update(s)
	}
	// Known lock contention must not become the normal baseline during warmup.
	if len(d.samples) < d.size {
		if s.LockWaiters == 0 && len(s.Blocking.Edges) == 0 {
			d.samples = append(d.samples, s.OldestQuerySeconds)
			d.sqlHistory = sqlstats.AppendRecent(d.sqlHistory, s.SQL)
		}
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
		d.pending = nil
		d.pendingDropped = 0
		d.pendingSQL = sqlstats.Context{}
		if s.LockWaiters == 0 && len(s.Blocking.Edges) == 0 {
			d.addNormal(s.OldestQuerySeconds)
			d.sqlHistory = sqlstats.AppendRecent(d.sqlHistory, s.SQL)
		}
		return nil
	}
	if d.streak == 0 {
		d.started = s.At
		d.pendingSQL.Before = sqlstats.CloneReports(d.sqlHistory)
	}
	d.streak++
	d.pendingSQL.Observe(s.SQL)
	recordBlocking(&d.pending, &d.pendingDropped, s)
	if d.streak < d.confirm {
		return nil
	}
	d.current = &Incident{
		ID: fmt.Sprintf("%d", s.At.UnixNano()), StartedAt: d.started, DetectedAt: s.At,
		UpdatedAt: s.At, Status: Active, Revision: 1,
		BaselineSeconds: baseline, ThresholdSeconds: threshold,
		Hypothesis: "Причина пока не установлена: вырос возраст активных запросов",
		Evidence: []string{
			fmt.Sprintf("Самый старый активный запрос: %.2f s; baseline: %.2f s; порог: %.2f s; последовательных превышений: %d", s.OldestQuerySeconds, baseline, threshold, d.streak),
			fmt.Sprintf("Активных сессий: %d; ожидают Lock: %d", s.Active, s.LockWaiters),
		},
		NextSteps: []string{"Проверить pg_stat_statements и изменения планов; сопоставить с latency API и временем деплоя"},
		Blocking:  d.pending, BlockingSamplesDropped: d.pendingDropped,
		SQL: d.pendingSQL,
	}
	d.pendingSQL = sqlstats.Context{}
	d.pending = nil
	d.pendingDropped = 0
	d.explainBlocking()
	result := d.current.Clone()
	return &result
}

func (d *Detector) addNormal(age float64) {
	copy(d.samples, d.samples[1:])
	d.samples[len(d.samples)-1] = age
}

func recordBlocking(observations *[]BlockingObservation, dropped *int, s collector.Snapshot) {
	if s.LockWaiters == 0 && len(s.Blocking.Edges) == 0 {
		return
	}
	observation := BlockingObservation{At: s.At, OldestQuerySeconds: s.OldestQuerySeconds, LockWaiters: s.LockWaiters, Graph: s.Blocking.Clone()}
	if len(*observations) == maxBlockingObservations {
		// Preserve the onset and bound memory even during a long outage/incident.
		copy((*observations)[1:], (*observations)[2:])
		*observations = (*observations)[:maxBlockingObservations-1]
		(*dropped)++
	}
	*observations = append(*observations, observation)
}

func (d *Detector) explainBlocking() {
	i := d.current
	if len(i.Blocking) == 0 {
		return
	}
	i.Hypothesis = "Блокировки — возможная причина деградации"
	i.NextSteps = []string{"Проверить сохранённые связи waiter_pid → blocker_pid и начало транзакций участников, включая idle in transaction", "Владелец приложения должен проверить блокирующую транзакцию; после её завершения проверить исчезновение ожиданий и latency приложения"}
	// Preserve trigger evidence while refreshing the human-readable graph summary.
	i.Evidence = i.Evidence[:2]
	latest := i.Blocking[len(i.Blocking)-1]
	i.Evidence = append(i.Evidence, fmt.Sprintf("Снимок блокировок %s: %d ожидающих Lock; сохранено связей: %d. Ожидания наблюдались в эпизоде роста возраста запросов; влияние на latency API не измерено", latest.At.Format(time.RFC3339), latest.LockWaiters, len(latest.Graph.Edges)))
	// Bound notification size. The API contains the complete captured graph.
	for n, edge := range latest.Graph.Edges {
		if n == 8 {
			i.Evidence = append(i.Evidence, "Остальные связи доступны в HTTP API")
			break
		}
		description := fmt.Sprintf("PID %d ждёт PID %d", edge.WaiterPID, edge.BlockerPID)
		if edge.BlockerPID == 0 {
			description += " (prepared transaction; backend отсутствует)"
		}
		for _, session := range latest.Graph.Sessions {
			if session.PID == edge.WaiterPID && session.State == "active" && session.QueryStartedAt != nil {
				age := math.Max(0, latest.At.Sub(*session.QueryStartedAt).Seconds())
				description += fmt.Sprintf("; возраст запроса ожидающего: %.2f s", age)
			}
			if session.PID != edge.BlockerPID {
				continue
			}
			description += fmt.Sprintf("; состояние блокирующего: %s", session.State)
			if session.TransactionStartedAt != nil {
				description += "; транзакция с " + session.TransactionStartedAt.Format(time.RFC3339)
			}
		}
		i.Evidence = append(i.Evidence, description)
	}
	if len(latest.Graph.Edges) == 0 {
		i.Evidence = append(i.Evidence, "Lock waits наблюдались, но блокирующие PID в этом снимке не установлены")
	}
}

func (d *Detector) update(s collector.Snapshot) *Incident {
	i := d.current
	i.UpdatedAt = s.At
	i.Revision++
	i.SQL.Observe(s.SQL)
	recordBlocking(&i.Blocking, &i.BlockingSamplesDropped, s)
	d.explainBlocking()
	if s.OldestQuerySeconds <= i.ThresholdSeconds && s.LockWaiters == 0 && len(s.Blocking.Edges) == 0 {
		if i.RecoverySamples == 0 {
			at := s.At
			i.RecoveryStartedAt = &at
		}
		i.RecoverySamples++
	} else {
		i.RecoverySamples = 0
		i.RecoveryStartedAt = nil
	}
	if i.RecoverySamples >= d.confirm {
		at := s.At
		i.Status = Resolved
		i.RecoveredAt = &at
		i.Evidence = append(i.Evidence, fmt.Sprintf("Восстановление наблюдаемых симптомов: %d последовательных снимков без Lock waits и с возрастом запросов ≤ %.2f s. Восстановление latency приложения не проверялось", i.RecoverySamples, i.ThresholdSeconds))
		d.current = nil
		d.streak = 0
		d.addNormal(s.OldestQuerySeconds)
		d.sqlHistory = sqlstats.AppendRecent(nil, s.SQL)
	}
	result := i.Clone()
	return &result
}
