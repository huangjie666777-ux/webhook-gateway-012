package webhook

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// CreateEndpoint stores a new endpoint and returns its first signing key.
func (s *SQLiteStore) CreateEndpoint(ctx context.Context, tenant, endpointURL string) (Endpoint, SigningKey, error) {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return Endpoint{}, SigningKey{}, errors.New("webhook: tenant is required")
	}
	if err := ValidateEndpointURL(endpointURL, s.opts.AllowPrivateURL); err != nil {
		return Endpoint{}, SigningKey{}, err
	}
	id, err := randomID("ep_", 16)
	if err != nil {
		return Endpoint{}, SigningKey{}, err
	}
	keyID, err := randomID("key_", 16)
	if err != nil {
		return Endpoint{}, SigningKey{}, err
	}
	secret, err := newSecret()
	if err != nil {
		return Endpoint{}, SigningKey{}, err
	}
	now := s.opts.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Endpoint{}, SigningKey{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO endpoints(id, tenant, url, active, created_at) VALUES(?,?,?,1,?)`,
		id, tenant, strings.TrimSpace(endpointURL), now); err != nil {
		return Endpoint{}, SigningKey{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO signing_keys(id, endpoint_id, secret, active, created_at) VALUES(?,?,?,1,?)`,
		keyID, id, secret, now); err != nil {
		return Endpoint{}, SigningKey{}, err
	}
	if err := tx.Commit(); err != nil {
		return Endpoint{}, SigningKey{}, err
	}
	ep := Endpoint{ID: id, Tenant: tenant, URL: strings.TrimSpace(endpointURL), Active: true}
	return ep, SigningKey{ID: keyID, EndpointID: id, Secret: secret, Active: true, CreatedAt: now}, nil
}

// ListEndpoints returns a tenant's endpoints in stable id order.
func (s *SQLiteStore) ListEndpoints(ctx context.Context, tenant string) ([]Endpoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant, url, active FROM endpoints WHERE tenant=? ORDER BY id ASC`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Endpoint
	for rows.Next() {
		var ep Endpoint
		var active int
		if err := rows.Scan(&ep.ID, &ep.Tenant, &ep.URL, &active); err != nil {
			return nil, err
		}
		ep.Active = active == 1
		out = append(out, ep)
	}
	return out, rows.Err()
}

// GetEndpoint enforces tenant isolation; cross-tenant reads look like 404.
func (s *SQLiteStore) GetEndpoint(ctx context.Context, tenant, endpointID string) (Endpoint, error) {
	return s.queryEndpoint(ctx, s.db, tenant, endpointID)
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *SQLiteStore) queryEndpoint(ctx context.Context, q rowQuerier, tenant, endpointID string) (Endpoint, error) {
	var ep Endpoint
	var active int
	err := q.QueryRowContext(ctx,
		`SELECT id, tenant, url, active FROM endpoints WHERE id=? AND tenant=?`, endpointID, tenant).
		Scan(&ep.ID, &ep.Tenant, &ep.URL, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return Endpoint{}, ErrNotFound
	}
	if err != nil {
		return Endpoint{}, err
	}
	ep.Active = active == 1
	return ep, nil
}

// endpointForIngest looks up an active endpoint by id without a tenant claim.
func (s *SQLiteStore) endpointForIngest(ctx context.Context, tx *sql.Tx, endpointID string) (Endpoint, error) {
	var ep Endpoint
	var active int
	err := tx.QueryRowContext(ctx,
		`SELECT id, tenant, url, active FROM endpoints WHERE id=?`, endpointID).
		Scan(&ep.ID, &ep.Tenant, &ep.URL, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return Endpoint{}, ErrNotFound
	}
	if err != nil {
		return Endpoint{}, err
	}
	ep.Active = active == 1
	if !ep.Active {
		return Endpoint{}, ErrNotFound
	}
	return ep, nil
}

// CreateKey issues a new signing key, optionally deactivating previous keys
// for rotation. The secret is returned exactly once.
func (s *SQLiteStore) CreateKey(ctx context.Context, tenant, endpointID string, deactivatePrevious bool) (SigningKey, error) {
	if _, err := s.GetEndpoint(ctx, tenant, endpointID); err != nil {
		return SigningKey{}, err
	}
	keyID, err := randomID("key_", 16)
	if err != nil {
		return SigningKey{}, err
	}
	secret, err := newSecret()
	if err != nil {
		return SigningKey{}, err
	}
	now := s.opts.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SigningKey{}, err
	}
	defer tx.Rollback()
	if deactivatePrevious {
		if _, err := tx.ExecContext(ctx,
			`UPDATE signing_keys SET active=0 WHERE endpoint_id=? AND active=1`, endpointID); err != nil {
			return SigningKey{}, err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO signing_keys(id, endpoint_id, secret, active, created_at) VALUES(?,?,?,1,?)`,
		keyID, endpointID, secret, now); err != nil {
		return SigningKey{}, err
	}
	if err := tx.Commit(); err != nil {
		return SigningKey{}, err
	}
	return SigningKey{ID: keyID, EndpointID: endpointID, Secret: secret, Active: true, CreatedAt: now}, nil
}

// DeactivateKey retires a key so it can no longer sign inbound events.
func (s *SQLiteStore) DeactivateKey(ctx context.Context, tenant, endpointID, keyID string) error {
	if _, err := s.GetEndpoint(ctx, tenant, endpointID); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE signing_keys SET active=0 WHERE id=? AND endpoint_id=?`, keyID, endpointID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
