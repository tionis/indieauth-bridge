package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eric/indieauth-bridge/internal/backends"
	"github.com/eric/indieauth-bridge/internal/security"
	_ "modernc.org/sqlite"
)

type SQLite struct {
	db *sql.DB
}

func OpenSQLite(ctx context.Context, path string) (*SQLite, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &SQLite{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLite) Close() error {
	return s.db.Close()
}

func (s *SQLite) migrate(ctx context.Context) error {
	pragmas := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at INTEGER NOT NULL
		)`,
	}
	for _, stmt := range pragmas {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if err := s.applyMigration(ctx, 1, "initial_schema", []string{
		`CREATE TABLE IF NOT EXISTS auth_requests (
			id TEXT PRIMARY KEY,
			backend TEXT NOT NULL,
			backend_state TEXT NOT NULL,
			backend_state_value TEXT NOT NULL,
			me TEXT NOT NULL,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT NOT NULL,
			client_state TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			code_challenge_method TEXT NOT NULL,
			profile_json BLOB,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_requests_backend_state ON auth_requests(backend, backend_state_value)`,
		`CREATE TABLE IF NOT EXISTS authorization_codes (
			code_hash TEXT PRIMARY KEY,
			me TEXT NOT NULL,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			code_challenge_method TEXT NOT NULL,
			profile_json BLOB,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			used_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS access_tokens (
			token_hash TEXT PRIMARY KEY,
			me TEXT NOT NULL,
			client_id TEXT NOT NULL,
			scope TEXT NOT NULL,
			profile_json BLOB,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS consent_requests (
			id TEXT PRIMARY KEY,
			csrf_token TEXT NOT NULL,
			me TEXT NOT NULL,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT NOT NULL,
			client_state TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			code_challenge_method TEXT NOT NULL,
			profile_json BLOB,
			subject TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT NOT NULL,
			subject TEXT,
			me TEXT,
			client_id TEXT,
			created_at INTEGER NOT NULL
		)`,
	}); err != nil {
		return err
	}
	if err := s.applyMigration(ctx, 2, "access_token_revocation", []string{
		`ALTER TABLE access_tokens ADD COLUMN revoked_at INTEGER`,
	}); err != nil {
		return err
	}
	return nil
}

func (s *SQLite) applyMigration(ctx context.Context, version int, name string, stmts []string) error {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM schema_migrations WHERE version = ?`, version).Scan(&exists)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil && !isDuplicateColumnError(err) {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`, version, name, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func isDuplicateColumnError(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "duplicate column")
}

func (s *SQLite) CreateAuthRequest(ctx context.Context, ar AuthRequest) error {
	stateJSON, err := json.Marshal(ar.BackendState)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO auth_requests
		(id, backend, backend_state, backend_state_value, me, client_id, redirect_uri, scope, client_state, code_challenge, code_challenge_method, profile_json, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ar.ID, ar.Backend, stateJSON, ar.BackendState.State, ar.Me, ar.ClientID, ar.RedirectURI, ar.Scope, ar.ClientState,
		ar.CodeChallenge, ar.CodeChallengeMethod, ar.ProfileJSON, ar.ExpiresAt.Unix(), ar.CreatedAt.Unix())
	return err
}

func (s *SQLite) GetAuthRequestByBackendState(ctx context.Context, backendName, state string) (AuthRequest, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, backend, backend_state, me, client_id, redirect_uri, scope, client_state,
		code_challenge, code_challenge_method, profile_json, expires_at, created_at
		FROM auth_requests WHERE backend = ? AND backend_state_value = ?`, backendName, state)
	var ar AuthRequest
	var stateJSON []byte
	var expiresAt, createdAt int64
	err := row.Scan(&ar.ID, &ar.Backend, &stateJSON, &ar.Me, &ar.ClientID, &ar.RedirectURI, &ar.Scope, &ar.ClientState,
		&ar.CodeChallenge, &ar.CodeChallengeMethod, &ar.ProfileJSON, &expiresAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthRequest{}, ErrNotFound
	}
	if err != nil {
		return AuthRequest{}, err
	}
	if err := json.Unmarshal(stateJSON, &ar.BackendState); err != nil {
		return AuthRequest{}, err
	}
	ar.ExpiresAt = time.Unix(expiresAt, 0)
	ar.CreatedAt = time.Unix(createdAt, 0)
	if time.Now().After(ar.ExpiresAt) {
		return AuthRequest{}, ErrExpired
	}
	return ar, nil
}

func (s *SQLite) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_requests WHERE id = ?`, id)
	return err
}

func (s *SQLite) CreateAuthorizationCode(ctx context.Context, code string, rec AuthorizationCode) error {
	rec.CodeHash = security.HashToken(code)
	_, err := s.db.ExecContext(ctx, `INSERT INTO authorization_codes
		(code_hash, me, client_id, redirect_uri, scope, code_challenge, code_challenge_method, profile_json, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.CodeHash, rec.Me, rec.ClientID, rec.RedirectURI, rec.Scope, rec.CodeChallenge, rec.CodeChallengeMethod,
		rec.ProfileJSON, rec.ExpiresAt.Unix(), rec.CreatedAt.Unix())
	return err
}

func (s *SQLite) ConsumeAuthorizationCode(ctx context.Context, code string, now time.Time) (AuthorizationCode, error) {
	hash := security.HashToken(code)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthorizationCode{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	row := tx.QueryRowContext(ctx, `SELECT code_hash, me, client_id, redirect_uri, scope, code_challenge, code_challenge_method,
		profile_json, expires_at, created_at, used_at FROM authorization_codes WHERE code_hash = ?`, hash)
	var rec AuthorizationCode
	var expiresAt, createdAt int64
	var usedAt sql.NullInt64
	err = row.Scan(&rec.CodeHash, &rec.Me, &rec.ClientID, &rec.RedirectURI, &rec.Scope, &rec.CodeChallenge, &rec.CodeChallengeMethod,
		&rec.ProfileJSON, &expiresAt, &createdAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthorizationCode{}, ErrNotFound
	}
	if err != nil {
		return AuthorizationCode{}, err
	}
	rec.ExpiresAt = time.Unix(expiresAt, 0)
	rec.CreatedAt = time.Unix(createdAt, 0)
	if usedAt.Valid {
		return AuthorizationCode{}, ErrUsed
	}
	if !now.Before(rec.ExpiresAt) {
		return AuthorizationCode{}, ErrExpired
	}
	result, err := tx.ExecContext(ctx, `UPDATE authorization_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL`, now.Unix(), hash)
	if err != nil {
		return AuthorizationCode{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return AuthorizationCode{}, err
	}
	if affected != 1 {
		return AuthorizationCode{}, ErrUsed
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationCode{}, err
	}
	return rec, nil
}

func (s *SQLite) CreateAccessToken(ctx context.Context, token string, rec AccessToken) error {
	rec.TokenHash = security.HashToken(token)
	_, err := s.db.ExecContext(ctx, `INSERT INTO access_tokens
		(token_hash, me, client_id, scope, profile_json, expires_at, created_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		rec.TokenHash, rec.Me, rec.ClientID, rec.Scope, rec.ProfileJSON, rec.ExpiresAt.Unix(), rec.CreatedAt.Unix())
	return err
}

func (s *SQLite) GetAccessToken(ctx context.Context, token string, now time.Time) (AccessToken, error) {
	hash := security.HashToken(token)
	row := s.db.QueryRowContext(ctx, `SELECT token_hash, me, client_id, scope, profile_json, expires_at, created_at, revoked_at
		FROM access_tokens WHERE token_hash = ?`, hash)
	var rec AccessToken
	var expiresAt, createdAt int64
	var revokedAt sql.NullInt64
	err := row.Scan(&rec.TokenHash, &rec.Me, &rec.ClientID, &rec.Scope, &rec.ProfileJSON, &expiresAt, &createdAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AccessToken{}, ErrNotFound
	}
	if err != nil {
		return AccessToken{}, err
	}
	rec.ExpiresAt = time.Unix(expiresAt, 0)
	rec.CreatedAt = time.Unix(createdAt, 0)
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		rec.RevokedAt = &t
		return AccessToken{}, ErrRevoked
	}
	if !now.Before(rec.ExpiresAt) {
		return AccessToken{}, ErrExpired
	}
	return rec, nil
}

func (s *SQLite) RevokeAccessToken(ctx context.Context, token string, now time.Time) error {
	hash := security.HashToken(token)
	_, err := s.db.ExecContext(ctx, `UPDATE access_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`, now.Unix(), hash)
	return err
}

func (s *SQLite) CreateConsentRequest(ctx context.Context, cr ConsentRequest) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO consent_requests
		(id, csrf_token, me, client_id, redirect_uri, scope, client_state, code_challenge, code_challenge_method, profile_json, subject, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cr.ID, cr.CSRFToken, cr.Me, cr.ClientID, cr.RedirectURI, cr.Scope, cr.ClientState, cr.CodeChallenge,
		cr.CodeChallengeMethod, cr.ProfileJSON, cr.Subject, cr.ExpiresAt.Unix(), cr.CreatedAt.Unix())
	return err
}

func (s *SQLite) GetConsentRequest(ctx context.Context, id string, now time.Time) (ConsentRequest, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, csrf_token, me, client_id, redirect_uri, scope, client_state,
		code_challenge, code_challenge_method, profile_json, subject, expires_at, created_at
		FROM consent_requests WHERE id = ?`, id)
	var cr ConsentRequest
	var expiresAt, createdAt int64
	err := row.Scan(&cr.ID, &cr.CSRFToken, &cr.Me, &cr.ClientID, &cr.RedirectURI, &cr.Scope, &cr.ClientState,
		&cr.CodeChallenge, &cr.CodeChallengeMethod, &cr.ProfileJSON, &cr.Subject, &expiresAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ConsentRequest{}, ErrNotFound
	}
	if err != nil {
		return ConsentRequest{}, err
	}
	cr.ExpiresAt = time.Unix(expiresAt, 0)
	cr.CreatedAt = time.Unix(createdAt, 0)
	if !now.Before(cr.ExpiresAt) {
		return ConsentRequest{}, ErrExpired
	}
	return cr, nil
}

func (s *SQLite) DeleteConsentRequest(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM consent_requests WHERE id = ?`, id)
	return err
}

func (s *SQLite) CreateAuditEvent(ctx context.Context, event AuditEvent) error {
	createdAt := event.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events (event_type, subject, me, client_id, created_at) VALUES (?, ?, ?, ?, ?)`,
		event.EventType, event.Subject, event.Me, event.ClientID, createdAt.Unix())
	return err
}

func (s *SQLite) Cleanup(ctx context.Context, now time.Time) error {
	cutoff := now.Unix()
	for _, stmt := range []string{
		`DELETE FROM auth_requests WHERE expires_at <= ?`,
		`DELETE FROM consent_requests WHERE expires_at <= ?`,
		`DELETE FROM authorization_codes WHERE expires_at <= ? OR used_at IS NOT NULL`,
		`DELETE FROM access_tokens WHERE expires_at <= ?`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt, cutoff); err != nil {
			return fmt.Errorf("cleanup: %w", err)
		}
	}
	return nil
}

func EncodeBackendState(state backends.BackendState) ([]byte, error) {
	return json.Marshal(state)
}
