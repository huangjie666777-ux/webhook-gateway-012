package webhook

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Sentinel errors returned by stores. They are mapped to stable JSON codes
// by the HTTP layer.
var (
	ErrNotFound          = errors.New("webhook: resource not found")
	ErrConflict          = errors.New("webhook: event id reused with different content")
	ErrInvalidSignature  = errors.New("webhook: signature verification failed")
	ErrInactiveKey       = errors.New("webhook: signing key is not active")
	ErrTimestampSkew     = errors.New("webhook: timestamp outside accepted window")
	ErrTooManyPending    = errors.New("webhook: endpoint has too many unfinished events")
	ErrInvalidURL        = errors.New("webhook: endpoint url is not allowed")
	ErrIncompleteHeaders = errors.New("webhook: signed event headers are required")
)

// SigningKey is returned exactly once at creation time; the secret is never
// logged or returned again.
type SigningKey struct {
	ID         string `json:"id"`
	EndpointID string `json:"endpoint_id"`
	Secret     string `json:"secret,omitempty"`
	Active     bool   `json:"active"`
	CreatedAt  int64  `json:"created_at"`
}

// InboundEvent carries the verified raw inbound request fields.
type InboundEvent struct {
	EndpointID  string
	EventID     string
	KeyID       string
	Timestamp   int64
	OrderingKey string
	ContentType string
	Payload     []byte
	Signature   string
}

// OutboundItem is one claimable delivery together with everything the worker
// needs to perform the POST.
type OutboundItem struct {
	Delivery
	EndpointID  string
	URL         string
	Payload     []byte
	ContentType string
	OrderingKey string
}

// FullStore is the durable storage boundary used by the HTTP layer and worker.
// The original WebhookStore interface stays available for lighter adapters.
type FullStore interface {
	WebhookStore
	Ping(context.Context) error
	CreateEndpoint(ctx context.Context, tenant, endpointURL string) (Endpoint, SigningKey, error)
	ListEndpoints(ctx context.Context, tenant string) ([]Endpoint, error)
	GetEndpoint(ctx context.Context, tenant, endpointID string) (Endpoint, error)
	CreateKey(ctx context.Context, tenant, endpointID string, deactivatePrevious bool) (SigningKey, error)
	DeactivateKey(ctx context.Context, tenant, endpointID, keyID string) error
	AcceptEvent(ctx context.Context, in InboundEvent) (Event, bool, error)
	GetEvent(ctx context.Context, tenant, endpointID, eventID string) (Event, error)
	ListEvents(ctx context.Context, tenant, endpointID string, limit int) ([]Event, error)
	ReplayEvent(ctx context.Context, tenant, endpointID, eventID string) error
	ClaimBatch(ctx context.Context, now time.Time, max int) ([]OutboundItem, error)
	RecordResult(ctx context.Context, item OutboundItem, statusCode int, errMsg string, at time.Time) error
}

// StoreOptions configures the SQLite store and its retry policy.
type StoreOptions struct {
	MaxPendingEvents int
	TimestampSkew    time.Duration
	MaxAttempts      int
	InitialBackoff   time.Duration
	MaxBackoff       time.Duration
	InflightTTL      time.Duration
	AllowPrivateURL  bool
	Now              func() time.Time
}

// SQLiteStore persists endpoints, signing keys, events and deliveries.
type SQLiteStore struct {
	db   *sql.DB
	opts StoreOptions
}

// OpenSQLiteStore opens (and initialises) the database at dbPath.
func OpenSQLiteStore(ctx context.Context, dbPath string, opts StoreOptions) (*SQLiteStore, error) {
	if opts.MaxPendingEvents == 0 {
		opts.MaxPendingEvents = 1000
	}
	if opts.TimestampSkew == 0 {
		opts.TimestampSkew = 5 * time.Minute
	}
	if opts.MaxAttempts == 0 {
		opts.MaxAttempts = 5
	}
	if opts.InitialBackoff == 0 {
		opts.InitialBackoff = time.Second
	}
	if opts.MaxBackoff == 0 {
		opts.MaxBackoff = time.Minute
	}
	if opts.InflightTTL == 0 {
		opts.InflightTTL = 30 * time.Second
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now() }
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	s := &SQLiteStore{db: db, opts: opts}
	if err := s.init(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// Ping verifies database connectivity for healthz.
func (s *SQLiteStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

const schemaSQL = `
CREATE TABLE IF NOT EXISTS endpoints (
	id         TEXT PRIMARY KEY,
	tenant     TEXT NOT NULL,
	url        TEXT NOT NULL,
	active     INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_endpoints_tenant ON endpoints(tenant, id);

CREATE TABLE IF NOT EXISTS signing_keys (
	id          TEXT PRIMARY KEY,
	endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
	secret      TEXT NOT NULL,
	active      INTEGER NOT NULL DEFAULT 1,
	created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_keys_endpoint ON signing_keys(endpoint_id, active);

CREATE TABLE IF NOT EXISTS events (
	endpoint_id  TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
	event_id     TEXT NOT NULL,
	payload      BLOB NOT NULL,
	content_type TEXT NOT NULL,
	key_id       TEXT NOT NULL,
	signature    TEXT NOT NULL,
	ordering_key TEXT NOT NULL DEFAULT '',
	seq          INTEGER NOT NULL,
	received_at  INTEGER NOT NULL,
	status       TEXT NOT NULL,
	PRIMARY KEY (endpoint_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_events_ep_seq ON events(endpoint_id, seq);

CREATE TABLE IF NOT EXISTS deliveries (
	endpoint_id     TEXT NOT NULL,
	event_id        TEXT NOT NULL,
	attempt         INTEGER NOT NULL DEFAULT 0,
	status          TEXT NOT NULL,
	next_attempt_at INTEGER NOT NULL,
	last_code       INTEGER NOT NULL DEFAULT 0,
	last_error      TEXT NOT NULL DEFAULT '',
	updated_at      INTEGER NOT NULL,
	PRIMARY KEY (endpoint_id, event_id),
	FOREIGN KEY (endpoint_id, event_id) REFERENCES events(endpoint_id, event_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(status, next_attempt_at);
`

func (s *SQLiteStore) init(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

func randomID(prefix string, nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidateEndpointURL enforces http(s), explicit hosts and blocks local or
// private destinations unless explicitly allowed (development/tests).
func ValidateEndpointURL(raw string, allowPrivate bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme must be http or https", ErrInvalidURL)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo is not allowed", ErrInvalidURL)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: host is required", ErrInvalidURL)
	}
	if !allowPrivate {
		for _, addr := range resolveHost(host) {
			if isBlockedAddr(addr) {
				return fmt.Errorf("%w: %s resolves to a blocked address", ErrInvalidURL, host)
			}
		}
	}
	return nil
}
