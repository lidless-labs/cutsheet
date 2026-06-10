package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// tokenPrefix marks Cutsheet API tokens so leaked ones are recognizable in
// scanners and logs without revealing anything about the secret bytes.
const tokenPrefix = "cst_"

// Token is one API bearer token. The plaintext is returned exactly once, by
// CreateToken; only the SHA-256 hash is stored.
type Token struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}

// CreateToken mints a new API token under the given name and returns the
// record plus the plaintext token. The plaintext is shown once and never
// recoverable: only its SHA-256 hash is persisted.
func (s *Store) CreateToken(ctx context.Context, name string) (Token, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Token{}, "", fmt.Errorf("generate token: %w", err)
	}
	plaintext := tokenPrefix + hex.EncodeToString(raw)
	hash := hashToken(plaintext)

	now := time.Now()
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO api_tokens (name, token_hash, created_at) VALUES (?, ?, ?)`,
		name, hash, formatTime(now))
	if err != nil {
		return Token{}, "", fmt.Errorf("create token %q: %w", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Token{}, "", fmt.Errorf("create token %q: %w", name, err)
	}
	return Token{ID: id, Name: name, CreatedAt: now.UTC()}, plaintext, nil
}

// ListTokens returns all API tokens (metadata only, never hashes) ordered by id.
func (s *Store) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at FROM api_tokens ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		var t Token
		var createdAt string
		if err := rows.Scan(&t.ID, &t.Name, &createdAt); err != nil {
			return nil, fmt.Errorf("list tokens: %w", err)
		}
		if t.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, fmt.Errorf("list tokens: parse created_at: %w", err)
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	return tokens, nil
}

// DeleteToken removes the token with the given id, or returns ErrNotFound.
func (s *Store) DeleteToken(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete token %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete token %d: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("token %d: %w", id, ErrNotFound)
	}
	return nil
}

// CountTokens returns the number of API tokens. Zero tokens switches the API
// into its localhost-only unauthenticated first-run mode.
func (s *Store) CountTokens(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_tokens`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count tokens: %w", err)
	}
	return n, nil
}

// ValidateToken reports whether plaintext matches a stored token. The
// comparison hashes the candidate and constant-time-compares the digest
// against every stored hash, so neither the lookup nor the compare leaks
// timing about stored token bytes.
func (s *Store) ValidateToken(ctx context.Context, plaintext string) (bool, error) {
	candidate := []byte(hashToken(plaintext))

	rows, err := s.db.QueryContext(ctx, `SELECT token_hash FROM api_tokens`)
	if err != nil {
		return false, fmt.Errorf("validate token: %w", err)
	}
	defer rows.Close()

	valid := false
	for rows.Next() {
		var stored string
		if err := rows.Scan(&stored); err != nil {
			return false, fmt.Errorf("validate token: %w", err)
		}
		if subtle.ConstantTimeCompare(candidate, []byte(stored)) == 1 {
			valid = true // keep scanning: constant work regardless of position
		}
	}
	if err := rows.Err(); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("validate token: %w", err)
	}
	return valid, nil
}

func hashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
