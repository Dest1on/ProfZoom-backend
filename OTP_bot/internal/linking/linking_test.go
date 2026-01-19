package linking

import (
	"context"
	"errors"
	"testing"
	"time"

	"otp_bot/internal/telegram"
)

func TestLinkTokenLifecycle(t *testing.T) {
	store := NewMemoryLinkTokenStore()
	linkStore := NewMemoryTelegramLinkStore()
	registrar := NewLinkTokenRegistrar(store, time.Minute, []byte("secret"))
	linker := NewTelegramLinker(store, linkStore, []byte("secret"))

	token := "token-123"
	userID := "user-1"
	if _, err := registrar.Register(context.Background(), userID, token, ""); err != nil {
		t.Fatalf("register token: %v", err)
	}

	result, err := linker.VerifyAndLink(context.Background(), token, 101)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if result.UserID != userID {
		t.Fatalf("unexpected user_id: %s", result.UserID)
	}

	if _, err := linker.VerifyAndLink(context.Background(), token, 101); !errors.Is(err, telegram.ErrAlreadyLinked) {
		t.Fatalf("expected already linked error, got %v", err)
	}
}

func TestLinkTokenExpired(t *testing.T) {
	store := NewMemoryLinkTokenStore()
	linkStore := NewMemoryTelegramLinkStore()
	registrar := NewLinkTokenRegistrar(store, time.Minute, []byte("secret"))
	linker := NewTelegramLinker(store, linkStore, []byte("secret"))
	registrar.clock = func() time.Time { return time.Now().Add(-2 * time.Minute) }
	linker.clock = func() time.Time { return time.Now().Add(2 * time.Minute) }

	token := "token-123"
	if _, err := registrar.Register(context.Background(), "user-1", token, ""); err != nil {
		t.Fatalf("register token: %v", err)
	}

	if _, err := linker.VerifyAndLink(context.Background(), token, 101); !errors.Is(err, telegram.ErrInvalidToken) {
		t.Fatalf("expected invalid token error, got %v", err)
	}
}

func TestLinkTokenAlreadyLinkedChat(t *testing.T) {
	store := NewMemoryLinkTokenStore()
	linkStore := NewMemoryTelegramLinkStore()
	registrar := NewLinkTokenRegistrar(store, time.Minute, []byte("secret"))
	linker := NewTelegramLinker(store, linkStore, []byte("secret"))

	_ = linkStore.LinkChat(context.Background(), TelegramLink{
		UserID:         "user-1",
		TelegramChatID: 101,
		VerifiedAt:     time.Now(),
	})

	token := "token-234"
	if _, err := registrar.Register(context.Background(), "user-2", token, ""); err != nil {
		t.Fatalf("register token: %v", err)
	}

	if _, err := linker.VerifyAndLink(context.Background(), token, 101); !errors.Is(err, telegram.ErrAlreadyLinked) {
		t.Fatalf("expected already linked error, got %v", err)
	}
}

func TestLinkTokenAlreadyLinkedUser(t *testing.T) {
	store := NewMemoryLinkTokenStore()
	linkStore := NewMemoryTelegramLinkStore()
	registrar := NewLinkTokenRegistrar(store, time.Minute, []byte("secret"))
	linker := NewTelegramLinker(store, linkStore, []byte("secret"))

	_ = linkStore.LinkChat(context.Background(), TelegramLink{
		UserID:         "user-1",
		TelegramChatID: 101,
		VerifiedAt:     time.Now(),
	})

	token := "token-345"
	if _, err := registrar.Register(context.Background(), "user-1", token, ""); err != nil {
		t.Fatalf("register token: %v", err)
	}

	if _, err := linker.VerifyAndLink(context.Background(), token, 202); !errors.Is(err, telegram.ErrAlreadyLinked) {
		t.Fatalf("expected already linked error, got %v", err)
	}
}
