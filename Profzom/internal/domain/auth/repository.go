package auth

import (
	"context"

	"profzom/internal/common"
)

type OTPRepository interface {
	UpsertCode(ctx context.Context, phone, code string, expiresAtUnix int64, attemptsLeft int) error
	VerifyCode(ctx context.Context, phone, code string, nowUnix int64) (bool, error)
	GetState(ctx context.Context, phone string) (*OTPState, error)
	InvalidateCode(ctx context.Context, phone string) error
	DeleteExpired(ctx context.Context, beforeUnix int64) error
}

type OTPState struct {
	Phone        string
	AttemptsLeft int
	ExpiresAt    int64
	RequestedAt  int64
}

type RefreshTokenRepository interface {
	Store(ctx context.Context, token RefreshToken) error
	GetByToken(ctx context.Context, token string) (*RefreshToken, error)
	Revoke(ctx context.Context, token string, revokedAtUnix int64) error
	RevokeAll(ctx context.Context, userID common.UUID, revokedAtUnix int64) error
}
