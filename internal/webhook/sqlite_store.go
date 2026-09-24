package webhook

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
)

var (
	ErrConflict        = errors.New("webhook event content conflict")
	ErrNotFound        = errors.New("webhook resource not found")
	ErrLimitExceeded   = errors.New("webhook limit exceeded")
	ErrInvalidEndpoint = errors.New("invalid webhook endpoint")
)

type SQLiteConfig struct {
	Path          string
	Now           func() time.Time
	MaxAttempts   int
	BaseBackoff   time.Duration
	MaxUnfinished int
}

type SQLiteStore struct {
	db            *sql.DB
	now           func() time.Time
	maxAttempts   int
	baseBackoff   time.Duration
	maxUnfinished int
}

type EndpointInput struct {
	ID     string
	Tenant string
	URL    string
}

type KeyInput struct {
	KeyID  string
	Secret string
}

type EventInput struct {
	ID          string
	Tenant      string
	EndpointID  string
	OrderingKey string
	Payload     []byte
	Signature   string
	KeyID       string
	Timestamp   int64
}

func (s *SQLiteStore) Accept(context.Context, string, string, []byte, string, string) (Event, bool, error) {
	return Event{}, false, ErrNotImplemented
}

type SigningKey struct {
	ID         string
	EndpointID string
	Tenant     string
	Secret     string
	Active     bool
	CreatedAt  int64
}

func NewSQLiteStore(ctx context.Context, cfg SQLiteConfig) (*SQLiteStore, error) {
	if cfg.Path == "" {
		cfg.Path = ":memory:"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = time.Second
	}
	if cfg.MaxUnfinished <= 0 {
		cfg.MaxUnfinished = 1000
	}
	dsn := cfg.Path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db, now: cfg.Now, maxAttempts: cfg.MaxAttempts, baseBackoff: cfg.BaseBackoff, maxUnfinished: cfg.MaxUnfinished}
	if err := store.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS endpoints (
			id TEXT NOT NULL,
			tenant TEXT NOT NULL,
			url TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			PRIMARY KEY(tenant, id)
		)`,
		`CREATE TABLE IF NOT EXISTS signing_keys (
			id TEXT NOT NULL,
			tenant TEXT NOT NULL,
			endpoint_id TEXT NOT NULL,
			secret TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			PRIMARY KEY(tenant, endpoint_id, id),
			FOREIGN KEY(tenant, endpoint_id) REFERENCES endpoints(tenant, id)
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			rowid INTEGER PRIMARY KEY AUTOINCREMENT,
			id TEXT NOT NULL,
			tenant TEXT NOT NULL,
			endpoint_id TEXT NOT NULL,
			ordering_key TEXT NOT NULL,
			payload BLOB NOT NULL,
			content_hash TEXT NOT NULL,
			signature TEXT NOT NULL,
			key_id TEXT NOT NULL,
			signed_at INTEGER NOT NULL,
			received_at INTEGER NOT NULL,
			UNIQUE(tenant, endpoint_id, id),
			FOREIGN KEY(tenant, endpoint_id) REFERENCES endpoints(tenant, id)
		)`,
		`CREATE TABLE IF NOT EXISTS deliveries (
			event_rowid INTEGER PRIMARY KEY REFERENCES events(rowid) ON DELETE CASCADE,
			attempt INTEGER NOT NULL DEFAULT 0,
			next_attempt_at INTEGER NOT NULL,
			status TEXT NOT NULL,
			last_code INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_events_endpoint ON events(tenant, endpoint_id, received_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_delivery_claim ON deliveries(status, next_attempt_at)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func ValidateEndpointURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%w: url must use http or https", ErrInvalidEndpoint)
	}
	if u.Host == "" || u.User != nil || strings.ContainsAny(u.Host, " \t\r\n") {
		return fmt.Errorf("%w: url host is required and credentials are forbidden", ErrInvalidEndpoint)
	}
	return nil
}

func (s *SQLiteStore) CreateEndpoint(ctx context.Context, in EndpointInput, key KeyInput) (Endpoint, SigningKey, error) {
	in.ID = strings.TrimSpace(in.ID)
	in.Tenant = strings.TrimSpace(in.Tenant)
	in.URL = strings.TrimSpace(in.URL)
	key.KeyID = strings.TrimSpace(key.KeyID)
	if in.ID == "" || in.Tenant == "" || key.KeyID == "" || key.Secret == "" {
		return Endpoint{}, SigningKey{}, fmt.Errorf("%w: id, tenant, key id and secret are required", ErrInvalidEndpoint)
	}
	if err := ValidateEndpointURL(in.URL); err != nil {
		return Endpoint{}, SigningKey{}, err
	}
	now := s.now().Unix()
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO endpoints(id, tenant, url, active, created_at) VALUES (?, ?, ?, 1, ?)`, in.ID, in.Tenant, in.URL, now); err != nil {
			return mapConstraint(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO signing_keys(id, tenant, endpoint_id, secret, active, created_at) VALUES (?, ?, ?, ?, 1, ?)`, key.KeyID, in.Tenant, in.ID, key.Secret, now); err != nil {
			return mapConstraint(err)
		}
		return nil
	})
	if err != nil {
		return Endpoint{}, SigningKey{}, err
	}
	return Endpoint{ID: in.ID, Tenant: in.Tenant, URL: in.URL, Active: true}, SigningKey{ID: key.KeyID, EndpointID: in.ID, Tenant: in.Tenant, Active: true, CreatedAt: now}, nil
}

func (s *SQLiteStore) RotateKey(ctx context.Context, tenant, endpointID string, key KeyInput) (SigningKey, error) {
	tenant, endpointID, key.KeyID = strings.TrimSpace(tenant), strings.TrimSpace(endpointID), strings.TrimSpace(key.KeyID)
	if tenant == "" || endpointID == "" || key.KeyID == "" || key.Secret == "" {
		return SigningKey{}, fmt.Errorf("%w: key id and secret are required", ErrInvalidEndpoint)
	}
	now := s.now().Unix()
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM endpoints WHERE tenant=? AND id=? AND active=1`, tenant, endpointID).Scan(&active); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE signing_keys SET active=0 WHERE tenant=? AND endpoint_id=? AND active=1`, tenant, endpointID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO signing_keys(id, tenant, endpoint_id, secret, active, created_at) VALUES (?, ?, ?, ?, 1, ?)`, key.KeyID, tenant, endpointID, key.Secret, now)
		return mapConstraint(err)
	})
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{ID: key.KeyID, Tenant: tenant, EndpointID: endpointID, Active: true, CreatedAt: now}, nil
}

func (s *SQLiteStore) ActiveKey(ctx context.Context, tenant, endpointID, keyID string) (SigningKey, error) {
	var k SigningKey
	var active activeBool
	err := s.db.QueryRowContext(ctx, `SELECT id, endpoint_id, tenant, secret, active, created_at FROM signing_keys WHERE tenant=? AND endpoint_id=? AND id=? AND active=1`, tenant, endpointID, keyID).Scan(&k.ID, &k.EndpointID, &k.Tenant, &k.Secret, &active, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SigningKey{}, ErrNotFound
	}
	k.Active = bool(active)
	return k, err
}

type activeBool bool

func (b *activeBool) Scan(v any) error {
	switch n := v.(type) {
	case int64:
		*b = n != 0
	case int:
		*b = n != 0
	default:
		return fmt.Errorf("unexpected active value %T", v)
	}
	return nil
}

func (s *SQLiteStore) Endpoint(ctx context.Context, tenant, id string) (Endpoint, error) {
	var e Endpoint
	var active activeBool
	err := s.db.QueryRowContext(ctx, `SELECT id, tenant, url, active FROM endpoints WHERE tenant=? AND id=?`, tenant, id).Scan(&e.ID, &e.Tenant, &e.URL, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return Endpoint{}, ErrNotFound
	}
	e.Active = bool(active)
	return e, err
}

func (s *SQLiteStore) ReceiveEvent(ctx context.Context, in EventInput) (Event, bool, error) {
	if in.OrderingKey == "" {
		in.OrderingKey = in.ID
	}
	hash := sha256.Sum256(in.Payload)
	contentHash := hex.EncodeToString(hash[:])
	now := s.now().Unix()
	var existing Event
	var existingHash string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var rowid int64
		var status string
		var signedAt int64
		err := tx.QueryRowContext(ctx, `SELECT e.rowid,e.id,e.endpoint_id,e.ordering_key,e.payload,e.content_hash,e.signature,e.key_id,e.signed_at,e.received_at,d.status
			FROM events e JOIN deliveries d ON d.event_rowid=e.rowid
			WHERE e.tenant=? AND e.endpoint_id=? AND e.id=?`, in.Tenant, in.EndpointID, in.ID).
			Scan(&rowid, &existing.ID, &existing.EndpointID, &existing.EventKey, &existing.Payload, &existingHash, &existing.Signature, &existing.KeyID, &signedAt, &existing.ReceivedAt, &status)
		if err == nil {
			existing.SignedAt = signedAt
			existing.Status = Status(status)
			if existingHash != contentHash {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var unfinished int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM deliveries d JOIN events e ON e.rowid=d.event_rowid WHERE e.tenant=? AND e.endpoint_id=? AND d.status != ?`, in.Tenant, in.EndpointID, StatusSucceeded).Scan(&unfinished); err != nil {
			return err
		}
		if unfinished >= s.maxUnfinished {
			return ErrLimitExceeded
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO events(id, tenant, endpoint_id, ordering_key, payload, content_hash, signature, key_id, signed_at, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, in.ID, in.Tenant, in.EndpointID, in.OrderingKey, in.Payload, contentHash, in.Signature, in.KeyID, in.Timestamp, now)
		if err != nil {
			return mapConstraint(err)
		}
		eventRowID, err := res.LastInsertId()
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO deliveries(event_rowid, attempt, next_attempt_at, status, last_code, last_error, updated_at) VALUES (?, 0, ?, ?, 0, '', ?)`, eventRowID, now, StatusPending, now)
		return err
	})
	if err != nil {
		return Event{}, false, err
	}
	if existing.ID != "" {
		return existing, true, nil
	}
	return Event{ID: in.ID, EndpointID: in.EndpointID, EventKey: in.OrderingKey, Payload: in.Payload, Signature: in.Signature, KeyID: in.KeyID, ReceivedAt: now, Status: StatusPending}, false, nil
}

func (s *SQLiteStore) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

type EventRecord struct {
	Event
	Tenant      string
	OrderingKey string
	RowID       int64
	Destination string
	Delivery    Delivery
}

func (s *SQLiteStore) ListEvents(ctx context.Context, tenant, endpointID string, limit int) ([]EventRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT e.rowid,e.id,e.endpoint_id,e.ordering_key,e.payload,e.signature,e.key_id,e.signed_at,e.received_at,d.attempt,d.next_attempt_at,d.status,d.last_code,d.last_error
		FROM events e JOIN deliveries d ON d.event_rowid=e.rowid
		WHERE e.tenant=? AND e.endpoint_id=? ORDER BY e.received_at DESC, e.rowid DESC LIMIT ?`, tenant, endpointID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventRecord
	for rows.Next() {
		var rec EventRecord
		if err := rows.Scan(&rec.RowID, &rec.ID, &rec.EndpointID, &rec.OrderingKey, &rec.Payload, &rec.Signature, &rec.KeyID, &rec.SignedAt, &rec.ReceivedAt, &rec.Delivery.Attempt, &rec.Delivery.NextAttempt, &rec.Delivery.Status, &rec.Delivery.LastCode, &rec.Delivery.LastError); err != nil {
			return nil, err
		}
		rec.Tenant = tenant
		rec.EventKey = rec.OrderingKey
		rec.Delivery.EventID = rec.ID
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) RecoverInFlight(ctx context.Context) error {
	now := s.now().Unix()
	_, err := s.db.ExecContext(ctx, `UPDATE deliveries SET status=?, next_attempt_at=?, updated_at=? WHERE status=?`, StatusPending, now, now, StatusDelivering)
	return err
}

func (s *SQLiteStore) Claim(ctx context.Context, tenant string, limit int) ([]Delivery, error) {
	records, err := s.ClaimEvents(ctx, tenant, limit)
	if err != nil {
		return nil, err
	}
	out := make([]Delivery, 0, len(records))
	for _, record := range records {
		out = append(out, record.Delivery)
	}
	return out, nil
}

func (s *SQLiteStore) ClaimEvents(ctx context.Context, _ string, limit int) ([]EventRecord, error) {
	if limit <= 0 {
		limit = 10
	}
	now := s.now().Unix()
	var claimed []EventRecord
	err := s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `WITH candidates AS (
			SELECT d.event_rowid, e.tenant, e.endpoint_id, e.id, e.ordering_key, e.payload, d.attempt, ep.url,
			ROW_NUMBER() OVER (PARTITION BY e.tenant, e.endpoint_id, e.ordering_key ORDER BY e.rowid) AS rn
			FROM deliveries d JOIN events e ON e.rowid=d.event_rowid JOIN endpoints ep ON ep.tenant=e.tenant AND ep.id=e.endpoint_id
			WHERE d.status IN (?, ?) AND d.next_attempt_at <= ?
		)
		SELECT c.event_rowid,c.tenant,c.endpoint_id,c.id,c.ordering_key,c.payload,c.attempt,c.url FROM candidates c WHERE c.rn=1
		ORDER BY c.attempt DESC, c.event_rowid LIMIT ?`, StatusPending, StatusRetrying, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		type item struct {
			rowID                                    int64
			tenant, endpointID, eventID, orderingKey string
			payload                                  []byte
			attempt                                  int
			url                                      string
		}
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.rowID, &it.tenant, &it.endpointID, &it.eventID, &it.orderingKey, &it.payload, &it.attempt, &it.url); err != nil {
				return err
			}
			items = append(items, it)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, it := range items {
			if _, err := tx.ExecContext(ctx, `UPDATE deliveries SET status=?, updated_at=? WHERE event_rowid=? AND attempt=? AND status IN (?, ?)`, StatusDelivering, now, it.rowID, it.attempt, StatusPending, StatusRetrying); err != nil {
				return err
			}
			d := Delivery{EventID: it.eventID, EventRowID: it.rowID, Attempt: it.attempt, NextAttempt: now, Status: StatusDelivering}
			claimed = append(claimed, EventRecord{
				RowID:       it.rowID,
				Tenant:      it.tenant,
				OrderingKey: it.orderingKey,
				Destination: it.url,
				Delivery:    d,
				Event:       Event{ID: it.eventID, EndpointID: it.endpointID, EventKey: it.orderingKey, Payload: it.payload, Status: StatusDelivering},
			})
		}
		return nil
	})
	return claimed, err
}

func (s *SQLiteStore) DeliveryPayload(ctx context.Context, eventID string) (EventRecord, error) {
	var rec EventRecord
	err := s.db.QueryRowContext(ctx, `SELECT e.rowid,e.id,e.endpoint_id,e.tenant,e.ordering_key,e.payload,e.signature,e.key_id,e.signed_at,e.received_at, ep.url,d.attempt,d.next_attempt_at,d.status,d.last_code,d.last_error
		FROM events e JOIN endpoints ep ON ep.tenant=e.tenant AND ep.id=e.endpoint_id JOIN deliveries d ON d.event_rowid=e.rowid WHERE e.id=?`, eventID).
		Scan(&rec.RowID, &rec.ID, &rec.EndpointID, &rec.Tenant, &rec.OrderingKey, &rec.Payload, &rec.Signature, &rec.KeyID, &rec.SignedAt, &rec.ReceivedAt, &rec.Destination, &rec.Delivery.Attempt, &rec.Delivery.NextAttempt, &rec.Delivery.Status, &rec.Delivery.LastCode, &rec.Delivery.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return EventRecord{}, ErrNotFound
	}
	rec.EventKey = rec.OrderingKey
	rec.Delivery.EventID = rec.ID
	return rec, err
}

func (s *SQLiteStore) Complete(ctx context.Context, eventID string, attempt, code int, deliveryErr string) error {
	return s.finish(ctx, eventID, 0, attempt, code, deliveryErr, true)
}

func (s *SQLiteStore) CompleteAttempt(ctx context.Context, rowID int64, attempt, code int, deliveryErr string, retryable bool) error {
	return s.finish(ctx, "", rowID, attempt, code, deliveryErr, retryable)
}

func (s *SQLiteStore) finish(ctx context.Context, eventID string, rowID int64, attempt, code int, deliveryErr string, retryable bool) error {
	now := s.now()
	failed := code < 200 || code > 299
	nextAttempt := attempt + 1
	return s.tx(ctx, func(tx *sql.Tx) error {
		var currentRowID int64
		var status Status
		var query string
		var args []any
		if rowID != 0 {
			query = `SELECT event_rowid,status FROM deliveries WHERE event_rowid=? AND attempt=?`
			args = []any{rowID, attempt}
		} else {
			query = `SELECT d.event_rowid,d.status FROM deliveries d JOIN events e ON e.rowid=d.event_rowid WHERE e.id=? AND d.attempt=?`
			args = []any{eventID, attempt}
		}
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&currentRowID, &status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if status != StatusDelivering {
			return nil
		}
		if !failed {
			_, err := tx.ExecContext(ctx, `UPDATE deliveries SET status=?,last_code=?,last_error='',updated_at=? WHERE event_rowid=?`, StatusSucceeded, code, now.Unix(), currentRowID)
			return err
		}
		if !retryable || nextAttempt >= s.maxAttempts {
			_, err := tx.ExecContext(ctx, `UPDATE deliveries SET status=?,last_code=?,last_error=?,updated_at=? WHERE event_rowid=?`, StatusDead, code, safeError(deliveryErr), now.Unix(), currentRowID)
			return err
		}
		backoff := s.baseBackoff << (nextAttempt - 1)
		_, err := tx.ExecContext(ctx, `UPDATE deliveries SET attempt=?,status=?,next_attempt_at=?,last_code=?,last_error=?,updated_at=? WHERE event_rowid=?`, nextAttempt, StatusRetrying, now.Add(backoff).Unix(), code, safeError(deliveryErr), now.Unix(), currentRowID)
		return err
	})
}

func (s *SQLiteStore) ReplayEvent(ctx context.Context, tenant, endpointID, eventID string) (Delivery, error) {
	now := s.now().Unix()
	var d Delivery
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var rowID int64
		if err := tx.QueryRowContext(ctx, `SELECT e.rowid FROM events e WHERE e.tenant=? AND e.endpoint_id=? AND e.id=?`, tenant, endpointID, eventID).Scan(&rowID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE deliveries SET attempt=0,next_attempt_at=?,status=?,last_code=0,last_error='',updated_at=? WHERE event_rowid=? AND status != ?`, now, StatusPending, now, rowID, StatusDelivering)
		return err
	})
	if err == nil {
		d = Delivery{EventID: eventID, Status: StatusPending, NextAttempt: now}
	}
	return d, err
}

func safeError(v string) string {
	if len(v) > 500 {
		return v[:500]
	}
	return v
}

func mapConstraint(err error) error {
	var dbErr *sqlite.Error
	code := dbErr.Code()
	if errors.As(err, &dbErr) && (code == 2067 || code == 1555 || code == 19) {
		return ErrConflict
	}
	return err
}
