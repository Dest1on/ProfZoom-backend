package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"profzom/internal/common"
	"profzom/internal/domain/auth"
)

type OTPRepository struct {
	db *sql.DB
}

func NewOTPRepository(db *sql.DB) *OTPRepository {
	return &OTPRepository{db: db}
}

func (r *OTPRepository) UpsertCode(ctx context.Context, phone, code string, expiresAtUnix int64, attemptsLeft int) error {
	codeHash := hashOTP(code)
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, `INSERT INTO otp_codes (phone, code_hash, expires_at, created_at, attempts, requested_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (phone) DO UPDATE SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, created_at = EXCLUDED.created_at, attempts = EXCLUDED.attempts, requested_at = EXCLUDED.requested_at`,
		phone, codeHash, time.Unix(expiresAtUnix, 0).UTC(), now, attemptsLeft, now)
	if err != nil {
		return common.NewError(common.CodeInternal, "failed to store otp", err)
	}
	return nil
}

func (r *OTPRepository) VerifyCode(ctx context.Context, phone, code string, nowUnix int64) (bool, error) {
	row := r.db.QueryRowContext(ctx, `SELECT code_hash, expires_at, attempts FROM otp_codes WHERE phone = $1`, phone)
	var storedHash string
	var expiresAt time.Time
	var attemptsLeft int
	if err := row.Scan(&storedHash, &expiresAt, &attemptsLeft); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, common.NewError(common.CodeInternal, "failed to load otp", err)
	}
	if attemptsLeft <= 0 {
		if err := r.InvalidateCode(ctx, phone); err != nil {
			return false, err
		}
		return false, nil
	}
	if expiresAt.Before(time.Unix(nowUnix, 0).UTC()) {
		if err := r.InvalidateCode(ctx, phone); err != nil {
			return false, err
		}
		return false, nil
	}
	if storedHash != hashOTP(code) {
		attemptsLeft--
		if attemptsLeft <= 0 {
			if err := r.InvalidateCode(ctx, phone); err != nil {
				return false, err
			}
			return false, nil
		}
		_, err := r.db.ExecContext(ctx, `UPDATE otp_codes SET attempts = $1 WHERE phone = $2`, attemptsLeft, phone)
		if err != nil {
			return false, common.NewError(common.CodeInternal, "failed to update otp attempts", err)
		}
		return false, nil
	}
	return true, nil
}

func (r *OTPRepository) GetState(ctx context.Context, phone string) (*auth.OTPState, error) {
	row := r.db.QueryRowContext(ctx, `SELECT phone, attempts, expires_at, requested_at FROM otp_codes WHERE phone = $1`, phone)
	var state auth.OTPState
	var expiresAt time.Time
	var requestedAt time.Time
	if err := row.Scan(&state.Phone, &state.AttemptsLeft, &expiresAt, &requestedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, common.NewError(common.CodeInternal, "failed to load otp state", err)
	}
	state.ExpiresAt = expiresAt.Unix()
	state.RequestedAt = requestedAt.Unix()
	return &state, nil
}

func (r *OTPRepository) InvalidateCode(ctx context.Context, phone string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM otp_codes WHERE phone = $1`, phone)
	if err != nil {
		return common.NewError(common.CodeInternal, "failed to invalidate otp", err)
	}
	return nil
}

func (r *OTPRepository) DeleteExpired(ctx context.Context, beforeUnix int64) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM otp_codes WHERE expires_at < $1`, time.Unix(beforeUnix, 0).UTC())
	if err != nil {
		return common.NewError(common.CodeInternal, "failed to delete expired otp", err)
	}
	return nil
}

type RefreshTokenRepository struct {
	db *sql.DB
}

func NewRefreshTokenRepository(db *sql.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

func (r *RefreshTokenRepository) Store(ctx context.Context, token auth.RefreshToken) error {
	hash := hashToken(token.Token)
	_, err := r.db.ExecContext(ctx, `INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)`,
		token.ID, token.UserID, hash, token.ExpiresAt, token.CreatedAt)
	if err != nil {
		return common.NewError(common.CodeInternal, "failed to store refresh token", err)
	}
	return nil
}

func (r *RefreshTokenRepository) GetByToken(ctx context.Context, token string) (*auth.RefreshToken, error) {
	hash := hashToken(token)
	row := r.db.QueryRowContext(ctx, `SELECT id, user_id, token_hash, expires_at, created_at, revoked_at FROM refresh_tokens WHERE token_hash = $1`, hash)
	var rt auth.RefreshToken
	var tokenHash string
	if err := row.Scan(&rt.ID, &rt.UserID, &tokenHash, &rt.ExpiresAt, &rt.CreatedAt, &rt.RevokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, common.NewError(common.CodeNotFound, "refresh token not found", err)
		}
		return nil, common.NewError(common.CodeInternal, "failed to load refresh token", err)
	}
	rt.Token = token
	return &rt, nil
}

func (r *RefreshTokenRepository) Revoke(ctx context.Context, token string, revokedAtUnix int64) error {
	hash := hashToken(token)
	_, err := r.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = $1 WHERE token_hash = $2`, time.Unix(revokedAtUnix, 0).UTC(), hash)
	if err != nil {
		return common.NewError(common.CodeInternal, "failed to revoke refresh token", err)
	}
	return nil
}

func (r *RefreshTokenRepository) RevokeAll(ctx context.Context, userID common.UUID, revokedAtUnix int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL`, time.Unix(revokedAtUnix, 0).UTC(), userID)
	if err != nil {
		return common.NewError(common.CodeInternal, "failed to revoke refresh tokens", err)
	}
	return nil
}

func hashOTP(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
