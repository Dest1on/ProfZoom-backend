package telegram

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubVerifier struct{}

func (stubVerifier) VerifyAndLink(ctx context.Context, token string, chatID int64) (LinkResult, error) {
	return LinkResult{UserID: "user-1"}, nil
}

func TestWebhookUnauthorized(t *testing.T) {
	sender := &fakeSender{}
	bot := NewBot(sender, stubVerifier{}, nil, nil, nil, slog.Default())
	handler := NewWebhookHandler(bot, "secret", slog.Default())

	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", bytes.NewBufferString(`{"update_id":1}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Result().StatusCode)
	}
}

func TestWebhookSuccess(t *testing.T) {
	sender := &fakeSender{}
	bot := NewBot(sender, stubVerifier{}, nil, nil, nil, slog.Default())
	handler := NewWebhookHandler(bot, "secret", slog.Default())

	payload := `{"update_id":1,"message":{"message_id":1,"chat":{"id":12,"type":"private"},"text":"/start PZ-ABC12345"}}`
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", bytes.NewBufferString(payload))
	req.Header.Set("X-Telegram-Bot-Api-Secret-Token", "secret")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Result().StatusCode)
	}
	if sender.lastChatID != 12 {
		t.Fatalf("expected chat id 12, got %d", sender.lastChatID)
	}
}
