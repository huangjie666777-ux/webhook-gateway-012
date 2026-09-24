package webhook

import (
	"context"
	"database/sql"
	"math"
	"time"
)

// ClaimBatch atomically claims due deliveries. Per (endpoint, ordering_key),
// only the oldest unfinished event is eligible, preserving receive order.
// Deliveries stuck in "delivering" from a crashed worker are recovered.
func (s *SQLiteStore) ClaimBatch(ctx context.Context, now time.Time, max int) ([]OutboundItem, error) {
	if max <= 0 {
		max = 16
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Recover stale in-flight rows from a crashed process. Rows still being
	// actively delivered (updated within InflightTTL) are left untouched.
	if _, err := tx.ExecContext(ctx,
		`UPDATE deliveries SET status=?, updated_at=? WHERE status=? AND updated_at < ?`,
		string(StatusRetrying), now.Unix(), string(StatusDelivering), now.Add(-s.opts.InflightTTL).Unix()); err != nil {
		return nil, err
	}

	rows, err := tx.QueryContext(ctx, `
SELECT d.endpoint_id, d.event_id, d.attempt, d.status, d.next_attempt_at, d.last_code, d.last_error,
       e.payload, e.content_type, e.ordering_key, ep.url
FROM deliveries d
JOIN events e ON e.endpoint_id=d.endpoint_id AND e.event_id=d.event_id
JOIN endpoints ep ON ep.id=d.endpoint_id AND ep.active=1
WHERE d.status IN (?, ?) AND d.next_attempt_at <= ?
  AND NOT EXISTS (
	SELECT 1 FROM events e2
	JOIN deliveries d2 ON d2.endpoint_id=e2.endpoint_id AND d2.event_id=e2.event_id
	WHERE e2.endpoint_id=d.endpoint_id AND e2.ordering_key=e.ordering_key
	  AND e2.seq < e.seq
	  AND d2.status IN (?, ?, ?)
  )
ORDER BY e.received_at ASC, d.endpoint_id ASC, e.seq ASC
LIMIT ?`,
		string(StatusPending), string(StatusRetrying), now.Unix(),
		string(StatusPending), string(StatusRetrying), string(StatusDelivering), max)
	if err != nil {
		return nil, err
	}
	type groupKey struct {
		ep  string
		ord string
	}
	seen := map[groupKey]bool{}
	var items []OutboundItem
	for rows.Next() {
		var it OutboundItem
		var status string
		if err := rows.Scan(&it.EndpointID, &it.EventID, &it.Attempt, &status, &it.NextAttempt,
			&it.LastCode, &it.LastError, &it.Payload, &it.ContentType, &it.OrderingKey, &it.URL); err != nil {
			rows.Close()
			return nil, err
		}
		k := groupKey{it.EndpointID, it.OrderingKey}
		if seen[k] {
			continue // strict head-of-line per ordering key in one batch
		}
		seen[k] = true
		it.Status = StatusDelivering
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range items {
		it := items[i]
		if _, err := tx.ExecContext(ctx,
			`UPDATE deliveries SET status=?, attempt=attempt+1, updated_at=? WHERE endpoint_id=? AND event_id=?`,
			string(StatusDelivering), now.Unix(), it.EndpointID, it.EventID); err != nil {
			return nil, err
		}
		items[i].Attempt++
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return items, nil
}

// RecordResult applies one attempt outcome transactionally. 2xx succeeds;
// retryable failures schedule deterministic exponential backoff; exhausted
// attempts mark the delivery and event as dead. Non-retryable 4xx responses
// (other than 408/429) fail immediately to dead.
func (s *SQLiteStore) RecordResult(ctx context.Context, item OutboundItem, statusCode int, errMsg string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	attempt := item.Attempt
	switch {
	case statusCode >= 200 && statusCode < 300:
		if err := applyState(ctx, tx, item, attempt, StatusSucceeded, 0, statusCode, "", at); err != nil {
			return err
		}
	case isRetryable(statusCode) && attempt < s.opts.MaxAttempts:
		next := at.Add(backoff(s.opts.InitialBackoff, s.opts.MaxBackoff, attempt)).Unix()
		if err := applyState(ctx, tx, item, attempt, StatusRetrying, next, statusCode, errMsg, at); err != nil {
			return err
		}
	default:
		if err := applyState(ctx, tx, item, attempt, StatusDead, 0, statusCode, errMsg, at); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func applyState(ctx context.Context, tx *sql.Tx, item OutboundItem, attempt int, status Status, nextAt int64, code int, errMsg string, at time.Time) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE deliveries SET status=?, attempt=?, next_attempt_at=?, last_code=?, last_error=?, updated_at=?
		 WHERE endpoint_id=? AND event_id=?`,
		string(status), attempt, nextAt, code, truncateErr(errMsg), at.Unix(), item.EndpointID, item.EventID)
	if err != nil {
		return err
	}
	eventStatus := status
	_, err = tx.ExecContext(ctx,
		`UPDATE events SET status=? WHERE endpoint_id=? AND event_id=?`,
		string(eventStatus), item.EndpointID, item.EventID)
	return err
}

func isRetryable(code int) bool {
	if code == 0 {
		return true // network error / timeout: no response received
	}
	switch code {
	case 408, 429:
		return true
	default:
		return code >= 500 && code <= 599
	}
}

// backoff is deterministic: initial * 2^(attempt-1), capped at max. attempt is
// 1-based for the attempt that just failed.
func backoff(initial, max time.Duration, attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	e := float64(attempt - 1)
	d := time.Duration(float64(initial) * math.Pow(2, e))
	if d > max || d <= 0 {
		return max
	}
	return d
}
