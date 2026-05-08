package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	stmts := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
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
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
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
		(token_hash, me, client_id, scope, profile_json, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rec.TokenHash, rec.Me, rec.ClientID, rec.Scope, rec.ProfileJSON, rec.ExpiresAt.Unix(), rec.CreatedAt.Unix())
	return err
}

func (s *SQLite) Cleanup(ctx context.Context, now time.Time) error {
	cutoff := now.Unix()
	for _, stmt := range []string{
		`DELETE FROM auth_requests WHERE expires_at <= ?`,
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
