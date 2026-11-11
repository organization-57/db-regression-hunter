package collector

import (
	"context"
	"time"
)

func (p *Postgres) LongRunning(ctx context.Context) ([]Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := p.db.QueryContext(ctx, `SELECT pid, COALESCE(application_name,''), COALESCE(state,'unknown'),
COALESCE(wait_event_type,''), COALESCE(wait_event,''),
COALESCE(GREATEST(0,extract(epoch FROM clock_timestamp()-xact_start)),0)::float8,
COALESCE(GREATEST(0,extract(epoch FROM clock_timestamp()-query_start)),0)::float8
FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND usename<>current_user AND state='active' AND query_start IS NOT NULL
ORDER BY query_start LIMIT 5`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []Session
	for rows.Next() {
		s := Session{TargetDatabase: true}
		if err := rows.Scan(&s.PID, &s.Application, &s.State, &s.WaitEventType, &s.WaitEvent, &s.TransactionAgeSeconds, &s.QueryAgeSeconds); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}
