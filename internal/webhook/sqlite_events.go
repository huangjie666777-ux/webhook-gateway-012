package webhook

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Accept satisfies the original WebhookStore boundary. The durable HTTP path
// uses AcceptEvent, which also carries the signed timestamp.
func (s *SQLiteStore) Accept(ctx context.Context, tenant, eventID string, payload []byte, signature, keyID string) (Event, bool, error) {
	return Event{}, false, fmt.Errorf("%w: use AcceptEvent with the signed timestamp", ErrIncompleteHeaders)
}

// Claim satisfies the original WebhookStore boundary; the worker uses
// ClaimBatch which includes payload and destination URL.
func (s *SQLiteStore) Claim(ctx context.Context, endpointID string, max int) ([]Delivery, error) {
	items, err := s.ClaimBatch(ctx, s.opts.Now(), max)
	if err != nil {
		return nil, err
	}
	out := make([]Delivery, 0, len(items))
	for _, item := range items {
		if item.EndpointID == endpointID {
			out = append(out, item.Delivery)
		}
	}
	return out, nil
}

// Complete satisfies the original WebhookStore boundary.
func (s *SQLiteStore) Complete(ctx context.Context, eventID string, attempt, statusCode int, errMsg string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE deliveries SET attempt=?, last_code=?, last_error=?, updated_at=? WHERE event_id=?`,
		attempt, statusCode, truncateErr(errMsg), s.opts.Now().Unix(), eventID)
	return err
}

// AcceptEvent verifies the signature against an active key and persists the
// event and its initial pending delivery atomically. Identical duplicate
// submissions are idempotent; changed content returns ErrConflict. No row is
// written when verification fails.
func (s *SQLiteStore) AcceptEvent(ctx context.Context, in InboundEvent) (Event, bool, error) {
	if in.EventID == "" || in.KeyID == "" || in.Signature == "" || in.Timestamp <= 0 {
		return Event{}, false, ErrIncompleteHeaders
	}
	diff := s.opts.Now().Unix() - in.Timestamp
	if diff < 0 {
		diff = -diff
	}
	if time.Duration(diff)*time.Second > s.opts.TimestampSkew {
		return Event{}, false, ErrTimestampSkew
	}
	now := s.opts.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Event{}, false, err
	}
	defer tx.Rollback()

	if _, err := s.endpointForIngest(ctx, tx, in.EndpointID); err != nil {
		return Event{}, false, err
	}

	var secret string
	var keyActive int
	err = tx.QueryRowContext(ctx,
		`SELECT secret, active FROM signing_keys WHERE id=? AND endpoint_id=?`,
		in.KeyID, in.EndpointID).Scan(&secret, &keyActive)
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, false, ErrInvalidSignature
	}
	if err != nil {
		return Event{}, false, err
	}
	if keyActive != 1 {
		return Event{}, false, ErrInactiveKey
	}
	if !verifySignature(secret, fmt.Sprintf("%d", in.Timestamp), in.Signature, in.Payload) {
		return Event{}, false, ErrInvalidSignature
	}

	var existingPayload []byte
	var existingKey, existingSig string
	err = tx.QueryRowContext(ctx,
		`SELECT payload, key_id, signature FROM events WHERE endpoint_id=? AND event_id=?`,
		in.EndpointID, in.EventID).Scan(&existingPayload, &existingKey, &existingSig)
	switch {
	case err == nil:
		if bytesEqual(existingPayload, in.Payload) && existingKey == in.KeyID && existingSig == in.Signature {
			ev, gerr := s.getEventTx(ctx, tx, in.EndpointID, in.EventID)
			return ev, true, gerr // duplicate: no write
		}
		return Event{}, false, ErrConflict
	case !errors.Is(err, sql.ErrNoRows):
		return Event{}, false, err
	}

	var pending int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM deliveries WHERE endpoint_id=? AND status IN (?, ?)`,
		in.EndpointID, StatusPending, StatusDelivering).Scan(&pending); err != nil {
		return Event{}, false, err
	}
	if pending >= s.opts.MaxPendingEvents {
		return Event{}, false, ErrTooManyPending
	}

	var seq int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq),0)+1 FROM events WHERE endpoint_id=?`, in.EndpointID).Scan(&seq); err != nil {
		return Event{}, false, err
	}
	receivedAt := now.Unix()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO events(endpoint_id, event_id, payload, content_type, key_id, signature, ordering_key, seq, received_at, status)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		in.EndpointID, in.EventID, in.Payload, contentType(in.ContentType), in.KeyID, in.Signature,
		in.OrderingKey, seq, receivedAt, string(StatusPending)); err != nil {
		return Event{}, false, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO deliveries(endpoint_id, event_id, attempt, status, next_attempt_at, last_code, last_error, updated_at)
		 VALUES(?,?,0,?,0,0,'',?)`,
		in.EndpointID, in.EventID, string(StatusPending), receivedAt); err != nil {
		return Event{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Event{}, false, err
	}
	return Event{
		ID:         in.EventID,
		EndpointID: in.EndpointID,
		EventKey:   in.OrderingKey,
		Payload:    in.Payload,
		Signature:  in.Signature,
		KeyID:      in.KeyID,
		ReceivedAt: receivedAt,
		Status:     StatusPending,
	}, false, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contentType(ct string) string {
	if ct == "" {
		return "application/octet-stream"
	}
	return ct
}

func truncateErr(msg string) string {
	const maxErr = 512
	if len(msg) > maxErr {
		return msg[:maxErr]
	}
	return msg
}

const eventColumns = `event_id, endpoint_id, payload, key_id, ordering_key, received_at, status`

func scanEvent(scanner interface {
	Scan(dest ...any) error
}) (Event, error) {
	var ev Event
	var status string
	if err := scanner.Scan(&ev.ID, &ev.EndpointID, &ev.Payload, &ev.KeyID, &ev.EventKey, &ev.ReceivedAt, &status); err != nil {
		return Event{}, err
	}
	ev.Status = Status(status)
	return ev, nil
}

func (s *SQLiteStore) getEventTx(ctx context.Context, tx *sql.Tx, endpointID, eventID string) (Event, error) {
	ev, err := scanEvent(tx.QueryRowContext(ctx,
		`SELECT `+eventColumns+` FROM events WHERE endpoint_id=? AND event_id=?`, endpointID, eventID))
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, ErrNotFound
	}
	return ev, err
}

// GetEvent returns one event scoped to the tenant's endpoint.
func (s *SQLiteStore) GetEvent(ctx context.Context, tenant, endpointID, eventID string) (Event, error) {
	if _, err := s.GetEndpoint(ctx, tenant, endpointID); err != nil {
		return Event{}, err
	}
	ev, err := scanEvent(s.db.QueryRowContext(ctx,
		`SELECT `+eventColumns+` FROM events WHERE endpoint_id=? AND event_id=?`, endpointID, eventID))
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, ErrNotFound
	}
	return ev, err
}

// ListEvents returns newest events first with stable (seq DESC, event_id)
// ordering, capped by limit.
func (s *SQLiteStore) ListEvents(ctx context.Context, tenant, endpointID string, limit int) ([]Event, error) {
	if _, err := s.GetEndpoint(ctx, tenant, endpointID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+eventColumns+` FROM events WHERE endpoint_id=? ORDER BY seq DESC, event_id ASC LIMIT ?`,
		endpointID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ReplayEvent resets a terminal/retried delivery for redelivery in original
// order.
func (s *SQLiteStore) ReplayEvent(ctx context.Context, tenant, endpointID, eventID string) error {
	if _, err := s.GetEndpoint(ctx, tenant, endpointID); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE deliveries SET status=?, attempt=0, next_attempt_at=0, last_code=0, last_error='', updated_at=?
		 WHERE endpoint_id=? AND event_id=?`,
		string(StatusPending), s.opts.Now().Unix(), endpointID, eventID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE events SET status=? WHERE endpoint_id=? AND event_id=?`,
		string(StatusPending), endpointID, eventID); err != nil {
		return err
	}
	return tx.Commit()
}
