-- +goose Up
CREATE TABLE IF NOT EXISTS telegram_links (
    user_id TEXT PRIMARY KEY,
    phone TEXT NOT NULL UNIQUE,
    chat_id BIGINT NOT NULL UNIQUE,
    verified_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS telegram_link_tokens (
    token_hash BYTEA PRIMARY KEY,
    user_id TEXT NOT NULL,
    phone TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS telegram_link_tokens_expires_idx
    ON telegram_link_tokens (expires_at);

-- +goose Down
DROP TABLE IF EXISTS telegram_link_tokens;
DROP TABLE IF EXISTS telegram_links;
