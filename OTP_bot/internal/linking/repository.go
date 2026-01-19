package linking

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// LinkToken представляет собой короткоживущий токен для привязки ID чатов Telegram.
type LinkToken struct {
	TokenHash []byte
	UserID    string
	Phone     string
	ExpiresAt time.Time
}

// LinkTokenStore хранит токены для верификации.
type LinkTokenStore interface {
	Save(ctx context.Context, token LinkToken) error
	Consume(ctx context.Context, tokenHash []byte) (LinkToken, error)
}

// ErrLinkTokenNotFound сообщает о неверном или истекшем токене.
var ErrLinkTokenNotFound = errors.New("link token not found")

// MemoryLinkTokenStore хранит токены в памяти.
type MemoryLinkTokenStore struct {
	mu     sync.Mutex
	tokens map[string]LinkToken
}

// NewMemoryLinkTokenStore создает хранилище токенов в памяти.
func NewMemoryLinkTokenStore() *MemoryLinkTokenStore {
	return &MemoryLinkTokenStore{tokens: make(map[string]LinkToken)}
}

func (s *MemoryLinkTokenStore) Save(_ context.Context, token LinkToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, stored := range s.tokens {
		if token.UserID != "" && stored.UserID == token.UserID {
			delete(s.tokens, key)
			continue
		}
		if token.Phone != "" && stored.Phone == token.Phone {
			delete(s.tokens, key)
		}
	}
	s.tokens[hexToken(token.TokenHash)] = token
	return nil
}

func (s *MemoryLinkTokenStore) Consume(_ context.Context, tokenHash []byte) (LinkToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.tokens[hexToken(tokenHash)]
	if !ok {
		return LinkToken{}, ErrLinkTokenNotFound
	}
	delete(s.tokens, hexToken(tokenHash))
	if time.Now().After(stored.ExpiresAt) {
		return LinkToken{}, ErrLinkTokenNotFound
	}
	return stored, nil
}

// TelegramLink хранит связь между телефоном и чатом Telegram.
type TelegramLink struct {
	UserID         string
	Phone          string
	TelegramChatID int64
	VerifiedAt     time.Time
}

// TelegramLinkStore хранит сопоставления телефон-чат.
type TelegramLinkStore interface {
	GetByPhone(ctx context.Context, phone string) (TelegramLink, error)
	GetByUserID(ctx context.Context, userID string) (TelegramLink, error)
	GetByChatID(ctx context.Context, chatID int64) (TelegramLink, error)
	LinkChat(ctx context.Context, link TelegramLink) error
}

// ErrTelegramLinkNotFound сообщает об отсутствии связи с чатом.
var ErrTelegramLinkNotFound = errors.New("telegram link not found")
var ErrTelegramLinkExists = errors.New("telegram link already exists")

// MemoryTelegramLinkStore хранит связи в памяти.
type MemoryTelegramLinkStore struct {
	mu    sync.RWMutex
	links map[string]TelegramLink
	users map[string]TelegramLink
	chats map[int64]TelegramLink
}

// NewMemoryTelegramLinkStore создает хранилище связей в памяти.
func NewMemoryTelegramLinkStore() *MemoryTelegramLinkStore {
	return &MemoryTelegramLinkStore{
		links: make(map[string]TelegramLink),
		users: make(map[string]TelegramLink),
		chats: make(map[int64]TelegramLink),
	}
}

func (s *MemoryTelegramLinkStore) GetByPhone(_ context.Context, phone string) (TelegramLink, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if phone == "" {
		return TelegramLink{}, ErrTelegramLinkNotFound
	}
	link, ok := s.links[phone]
	if !ok {
		return TelegramLink{}, ErrTelegramLinkNotFound
	}
	return link, nil
}

func (s *MemoryTelegramLinkStore) GetByUserID(_ context.Context, userID string) (TelegramLink, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	link, ok := s.users[userID]
	if !ok {
		return TelegramLink{}, ErrTelegramLinkNotFound
	}
	return link, nil
}

func (s *MemoryTelegramLinkStore) GetByChatID(_ context.Context, chatID int64) (TelegramLink, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	link, ok := s.chats[chatID]
	if !ok {
		return TelegramLink{}, ErrTelegramLinkNotFound
	}
	return link, nil
}

func (s *MemoryTelegramLinkStore) LinkChat(_ context.Context, link TelegramLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[link.UserID]; ok {
		return ErrTelegramLinkExists
	}
	if link.Phone != "" {
		if _, ok := s.links[link.Phone]; ok {
			return ErrTelegramLinkExists
		}
	}
	if _, ok := s.chats[link.TelegramChatID]; ok {
		return ErrTelegramLinkExists
	}
	if link.Phone != "" {
		s.links[link.Phone] = link
	}
	s.users[link.UserID] = link
	s.chats[link.TelegramChatID] = link
	return nil
}

func hexToken(hash []byte) string {
	return fmt.Sprintf("%x", hash)
}
