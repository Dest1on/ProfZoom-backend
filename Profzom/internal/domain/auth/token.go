package auth

import (
	"time"

	"profzom/internal/common"
)

type RefreshToken struct {
	ID        common.UUID
	UserID    common.UUID
	Token     string
	Role      string
	ExpiresAt time.Time
	CreatedAt time.Time
	RevokedAt *time.Time
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}
