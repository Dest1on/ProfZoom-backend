package postgres

import (
	"context"
	"database/sql"
	"errors"

	"profzom/internal/common"
	"profzom/internal/domain/telegram"
)

type TelegramLinkRepository struct {
	db *sql.DB
}

func NewTelegramLinkRepository(db *sql.DB) *TelegramLinkRepository {
	return &TelegramLinkRepository{db: db}
}

func (r *TelegramLinkRepository) GetByChatID(ctx context.Context, chatID int64) (*telegram.Link, error) {
	row := r.db.QueryRowContext(ctx, `SELECT user_id, phone, chat_id, verified_at FROM telegram_links WHERE chat_id = $1`, chatID)
	var link telegram.Link
	if err := row.Scan(&link.UserID, &link.Phone, &link.ChatID, &link.VerifiedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, common.NewError(common.CodeNotFound, "telegram link not found", err)
		}
		return nil, common.NewError(common.CodeInternal, "failed to load telegram link", err)
	}
	return &link, nil
}

func (r *TelegramLinkRepository) GetByPhone(ctx context.Context, phone string) (*telegram.Link, error) {
	row := r.db.QueryRowContext(ctx, `SELECT user_id, phone, chat_id, verified_at FROM telegram_links WHERE phone = $1`, phone)
	var link telegram.Link
	if err := row.Scan(&link.UserID, &link.Phone, &link.ChatID, &link.VerifiedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, common.NewError(common.CodeNotFound, "telegram link not found", err)
		}
		return nil, common.NewError(common.CodeInternal, "failed to load telegram link", err)
	}
	return &link, nil
}
