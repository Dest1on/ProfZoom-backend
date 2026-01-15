package telegram

import (
	"context"
	"time"
)

type Link struct {
	UserID     string
	Phone      string
	ChatID     int64
	VerifiedAt time.Time
}

type LinkRepository interface {
	GetByChatID(ctx context.Context, chatID int64) (*Link, error)
	GetByPhone(ctx context.Context, phone string) (*Link, error)
}
