package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"profzom/internal/common"
	"profzom/internal/domain/analytics"
	"profzom/internal/domain/auth"
	"profzom/internal/domain/telegram"
	"profzom/internal/domain/user"
	"profzom/internal/integration/otpbot"
	"profzom/internal/security"
)

type fakeOTPRepo struct {
	mu      sync.Mutex
	entries map[string]*otpEntry
}

type otpEntry struct {
	hash         string
	expiresAt    int64
	attemptsLeft int
	requestedAt  int64
}

func newFakeOTPRepo() *fakeOTPRepo {
	return &fakeOTPRepo{entries: make(map[string]*otpEntry)}
}

func (r *fakeOTPRepo) UpsertCode(ctx context.Context, userID, code string, expiresAtUnix int64, attemptsLeft int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[userID] = &otpEntry{
		hash:         hashOTP(code),
		expiresAt:    expiresAtUnix,
		attemptsLeft: attemptsLeft,
		requestedAt:  time.Now().UTC().Unix(),
	}
	return nil
}

func (r *fakeOTPRepo) VerifyCode(ctx context.Context, userID, code string, nowUnix int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.entries[userID]
	if entry == nil {
		return false, nil
	}
	if entry.attemptsLeft <= 0 {
		delete(r.entries, userID)
		return false, nil
	}
	if entry.expiresAt <= nowUnix {
		delete(r.entries, userID)
		return false, nil
	}
	if entry.hash != hashOTP(code) {
		entry.attemptsLeft--
		if entry.attemptsLeft <= 0 {
			delete(r.entries, userID)
		}
		return false, nil
	}
	return true, nil
}

func (r *fakeOTPRepo) GetState(ctx context.Context, userID string) (*auth.OTPState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.entries[userID]
	if entry == nil {
		return nil, nil
	}
	return &auth.OTPState{
		UserID:       userID,
		AttemptsLeft: entry.attemptsLeft,
		ExpiresAt:    entry.expiresAt,
		RequestedAt:  entry.requestedAt,
	}, nil
}

func (r *fakeOTPRepo) InvalidateCode(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, userID)
	return nil
}

func (r *fakeOTPRepo) DeleteExpired(ctx context.Context, beforeUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for userID, entry := range r.entries {
		if entry.expiresAt <= beforeUnix {
			delete(r.entries, userID)
		}
	}
	return nil
}

type fakeUserRepo struct {
	mu      sync.Mutex
	byPhone map[string]*user.User
	byID    map[common.UUID]*user.User
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{
		byPhone: make(map[string]*user.User),
		byID:    make(map[common.UUID]*user.User),
	}
}

func (r *fakeUserRepo) FindByPhone(ctx context.Context, phone string) (*user.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	account := r.byPhone[phone]
	if account == nil {
		return nil, common.NewError(common.CodeNotFound, "user not found", nil)
	}
	return cloneUser(account), nil
}

func (r *fakeUserRepo) GetByID(ctx context.Context, id common.UUID) (*user.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	account := r.byID[id]
	if account == nil {
		return nil, common.NewError(common.CodeNotFound, "user not found", nil)
	}
	return cloneUser(account), nil
}

func (r *fakeUserRepo) Create(ctx context.Context, phone string) (*user.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := common.NewUUID()
	now := time.Now().UTC()
	account := &user.User{ID: id, Phone: phone, CreatedAt: now, UpdatedAt: now}
	if phone != "" {
		r.byPhone[phone] = account
	}
	r.byID[id] = account
	return cloneUser(account), nil
}

func (r *fakeUserRepo) SetRoles(ctx context.Context, userID common.UUID, roles []user.Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	account := r.byID[userID]
	if account == nil {
		return common.NewError(common.CodeNotFound, "user not found", nil)
	}
	account.Roles = append([]user.Role(nil), roles...)
	return nil
}

func (r *fakeUserRepo) ListRoles(ctx context.Context, userID common.UUID) ([]user.Role, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	account := r.byID[userID]
	if account == nil {
		return nil, common.NewError(common.CodeNotFound, "user not found", nil)
	}
	return append([]user.Role(nil), account.Roles...), nil
}

func cloneUser(account *user.User) *user.User {
	copy := *account
	copy.Roles = append([]user.Role(nil), account.Roles...)
	return &copy
}

type fakeRefreshTokenRepo struct {
	mu     sync.Mutex
	tokens map[string]auth.RefreshToken
}

func newFakeRefreshTokenRepo() *fakeRefreshTokenRepo {
	return &fakeRefreshTokenRepo{tokens: make(map[string]auth.RefreshToken)}
}

func (r *fakeRefreshTokenRepo) Store(ctx context.Context, token auth.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[token.Token] = token
	return nil
}

func (r *fakeRefreshTokenRepo) GetByToken(ctx context.Context, token string) (*auth.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.tokens[token]
	if !ok {
		return nil, common.NewError(common.CodeNotFound, "refresh token not found", nil)
	}
	copy := value
	return &copy, nil
}

func (r *fakeRefreshTokenRepo) Revoke(ctx context.Context, token string, revokedAtUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.tokens[token]
	if !ok {
		return common.NewError(common.CodeNotFound, "refresh token not found", nil)
	}
	revokedAt := time.Unix(revokedAtUnix, 0).UTC()
	value.RevokedAt = &revokedAt
	r.tokens[token] = value
	return nil
}

func (r *fakeRefreshTokenRepo) RevokeAll(ctx context.Context, userID common.UUID, revokedAtUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	revokedAt := time.Unix(revokedAtUnix, 0).UTC()
	for key, value := range r.tokens {
		if value.UserID == userID {
			value.RevokedAt = &revokedAt
			r.tokens[key] = value
		}
	}
	return nil
}

type noopAnalyticsRepo struct{}

func (noopAnalyticsRepo) Create(ctx context.Context, event analytics.Event) error {
	return nil
}

type fakeTelegramLinkRepo struct {
	mu    sync.Mutex
	links map[int64]*telegram.Link
}

func newFakeTelegramLinkRepo() *fakeTelegramLinkRepo {
	return &fakeTelegramLinkRepo{links: make(map[int64]*telegram.Link)}
}

func (r *fakeTelegramLinkRepo) GetByChatID(ctx context.Context, chatID int64) (*telegram.Link, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	link := r.links[chatID]
	if link == nil {
		return nil, common.NewError(common.CodeNotFound, "telegram link not found", nil)
	}
	copy := *link
	return &copy, nil
}

func (r *fakeTelegramLinkRepo) GetByPhone(ctx context.Context, phone string) (*telegram.Link, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, link := range r.links {
		if link.Phone == phone {
			copy := *link
			return &copy, nil
		}
	}
	return nil, common.NewError(common.CodeNotFound, "telegram link not found", nil)
}

func (r *fakeTelegramLinkRepo) GetByUserID(ctx context.Context, userID string) (*telegram.Link, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, link := range r.links {
		if link.UserID == userID {
			copy := *link
			return &copy, nil
		}
	}
	return nil, common.NewError(common.CodeNotFound, "telegram link not found", nil)
}

type fakeOTPBot struct {
	mu      sync.Mutex
	linkErr error
	links   []linkToken
}

type linkToken struct {
	userID string
	token  string
}

func (b *fakeOTPBot) GetTelegramStatus(ctx context.Context, phone string) (otpbot.Status, error) {
	return otpbot.Status{}, nil
}

func (b *fakeOTPBot) RegisterLinkToken(ctx context.Context, userID, token string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.links = append(b.links, linkToken{userID: userID, token: token})
	return b.linkErr
}

func (b *fakeOTPBot) SendOTP(ctx context.Context, phone, code string) error {
	return nil
}

func TestAuthServiceRegister_IssuesLinkCode(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	otpBot := &fakeOTPBot{}
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthService(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, otpBot, nil, time.Minute, time.Hour, 5*time.Minute)

	result, err := service.Register(context.Background())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.UserID == "" {
		t.Fatal("expected user_id to be returned")
	}
	if !strings.HasPrefix(result.LinkCode, "PZ-") {
		t.Fatalf("expected link code to have prefix, got %q", result.LinkCode)
	}
	if _, err := userRepo.GetByID(context.Background(), result.UserID); err != nil {
		t.Fatalf("expected user to exist, got %v", err)
	}
	if len(otpBot.links) != 1 {
		t.Fatalf("expected link token registration, got %d", len(otpBot.links))
	}
	if otpBot.links[0].userID != result.UserID.String() {
		t.Fatalf("expected user_id %s, got %s", result.UserID.String(), otpBot.links[0].userID)
	}
	if otpBot.links[0].token != result.LinkCode {
		t.Fatalf("expected link code %s, got %s", result.LinkCode, otpBot.links[0].token)
	}
}

func TestAuthServiceRequestOTPByTelegram(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	linkRepo := newFakeTelegramLinkRepo()
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthServiceWithTelegramLinks(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, nil, linkRepo, nil, time.Minute, time.Hour, 5*time.Minute)

	account, err := userRepo.Create(context.Background(), "")
	if err != nil {
		t.Fatalf("expected user created, got %v", err)
	}
	linkRepo.links[42] = &telegram.Link{ChatID: 42, UserID: account.ID.String()}

	result, err := service.RequestOTPByTelegram(context.Background(), 42)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(result.Code) {
		t.Fatalf("expected 6 digit code, got %q", result.Code)
	}
	entry := otpRepo.entries[account.ID.String()]
	if entry == nil {
		t.Fatal("expected otp to be stored")
	}
	if entry.hash == result.Code {
		t.Fatal("otp stored in plaintext")
	}
	if entry.attemptsLeft != otpMaxAttempts {
		t.Fatalf("expected attempts_left %d, got %d", otpMaxAttempts, entry.attemptsLeft)
	}
}

func TestAuthServiceVerifyOTP_Success(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthService(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, nil, nil, time.Minute, time.Hour, 5*time.Minute)

	account, err := userRepo.Create(context.Background(), "")
	if err != nil {
		t.Fatalf("expected user created, got %v", err)
	}
	code := "123456"
	otpRepo.entries[account.ID.String()] = &otpEntry{
		hash:         hashOTP(code),
		expiresAt:    time.Now().Add(5 * time.Minute).UTC().Unix(),
		attemptsLeft: otpMaxAttempts,
		requestedAt:  time.Now().UTC().Unix(),
	}

	pair, accountAfter, isNewUser, err := service.VerifyOTP(context.Background(), account.ID.String(), code, "student")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if pair == nil || pair.AccessToken == "" {
		t.Fatal("expected access token")
	}
	if !isNewUser {
		t.Fatal("expected is_new_user to be true")
	}
	if accountAfter == nil || len(accountAfter.Roles) != 1 || accountAfter.Roles[0] != user.RoleStudent {
		t.Fatal("expected student role to be assigned")
	}
	if _, ok := otpRepo.entries[account.ID.String()]; ok {
		t.Fatal("expected otp to be invalidated")
	}
}

func TestAuthServiceVerifyOTP_Expired(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthService(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, nil, nil, time.Minute, time.Hour, 5*time.Minute)

	account, err := userRepo.Create(context.Background(), "")
	if err != nil {
		t.Fatalf("expected user created, got %v", err)
	}
	code := "123456"
	otpRepo.entries[account.ID.String()] = &otpEntry{
		hash:         hashOTP(code),
		expiresAt:    time.Now().Add(-1 * time.Minute).UTC().Unix(),
		attemptsLeft: otpMaxAttempts,
		requestedAt:  time.Now().UTC().Unix(),
	}

	_, _, _, err = service.VerifyOTP(context.Background(), account.ID.String(), code, "")
	if !common.Is(err, common.CodeUnauthorized) {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
	if _, ok := otpRepo.entries[account.ID.String()]; ok {
		t.Fatal("expected otp to be invalidated")
	}
}

func TestAuthServiceVerifyOTP_AttemptsExceeded(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthService(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, nil, nil, time.Minute, time.Hour, 5*time.Minute)

	account, err := userRepo.Create(context.Background(), "")
	if err != nil {
		t.Fatalf("expected user created, got %v", err)
	}
	otpRepo.entries[account.ID.String()] = &otpEntry{
		hash:         hashOTP("000000"),
		expiresAt:    time.Now().Add(5 * time.Minute).UTC().Unix(),
		attemptsLeft: 1,
		requestedAt:  time.Now().UTC().Unix(),
	}

	_, _, _, err = service.VerifyOTP(context.Background(), account.ID.String(), "123456", "")
	if !common.Is(err, common.CodeUnauthorized) {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
	if _, ok := otpRepo.entries[account.ID.String()]; ok {
		t.Fatal("expected otp to be invalidated after attempts exceeded")
	}
}

func TestAuthServiceVerifyOTPByTelegram(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	linkRepo := newFakeTelegramLinkRepo()
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthServiceWithTelegramLinks(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, nil, linkRepo, nil, time.Minute, time.Hour, 5*time.Minute)

	account, err := userRepo.Create(context.Background(), "")
	if err != nil {
		t.Fatalf("expected user created, got %v", err)
	}
	linkRepo.links[7] = &telegram.Link{ChatID: 7, UserID: account.ID.String()}
	otpRepo.entries[account.ID.String()] = &otpEntry{
		hash:         hashOTP("123456"),
		expiresAt:    time.Now().Add(5 * time.Minute).UTC().Unix(),
		attemptsLeft: otpMaxAttempts,
		requestedAt:  time.Now().UTC().Unix(),
	}

	pair, accountAfter, isNewUser, err := service.VerifyOTPByTelegram(context.Background(), 7, "123456", "student")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if pair == nil || pair.AccessToken == "" {
		t.Fatal("expected access token")
	}
	if !isNewUser {
		t.Fatal("expected is_new_user to be true")
	}
	if accountAfter == nil || len(accountAfter.Roles) != 1 || accountAfter.Roles[0] != user.RoleStudent {
		t.Fatal("expected student role to be assigned")
	}
}

func hashOTP(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
