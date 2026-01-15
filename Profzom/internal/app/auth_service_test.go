package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
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

func (r *fakeOTPRepo) UpsertCode(ctx context.Context, phone, code string, expiresAtUnix int64, attemptsLeft int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[phone] = &otpEntry{
		hash:         hashOTP(code),
		expiresAt:    expiresAtUnix,
		attemptsLeft: attemptsLeft,
		requestedAt:  time.Now().UTC().Unix(),
	}
	return nil
}

func (r *fakeOTPRepo) VerifyCode(ctx context.Context, phone, code string, nowUnix int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.entries[phone]
	if entry == nil {
		return false, nil
	}
	if entry.attemptsLeft <= 0 {
		delete(r.entries, phone)
		return false, nil
	}
	if entry.expiresAt <= nowUnix {
		delete(r.entries, phone)
		return false, nil
	}
	if entry.hash != hashOTP(code) {
		entry.attemptsLeft--
		if entry.attemptsLeft <= 0 {
			delete(r.entries, phone)
		}
		return false, nil
	}
	return true, nil
}

func (r *fakeOTPRepo) GetState(ctx context.Context, phone string) (*auth.OTPState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.entries[phone]
	if entry == nil {
		return nil, nil
	}
	return &auth.OTPState{
		Phone:        phone,
		AttemptsLeft: entry.attemptsLeft,
		ExpiresAt:    entry.expiresAt,
		RequestedAt:  entry.requestedAt,
	}, nil
}

func (r *fakeOTPRepo) InvalidateCode(ctx context.Context, phone string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, phone)
	return nil
}

func (r *fakeOTPRepo) DeleteExpired(ctx context.Context, beforeUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for phone, entry := range r.entries {
		if entry.expiresAt <= beforeUnix {
			delete(r.entries, phone)
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
	r.byPhone[phone] = account
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

type fakeOTPBot struct {
	mu        sync.Mutex
	status    otpbot.Status
	statusErr error
	sendErr   error
	linkErr   error
	sent      []sentOTP
	links     []linkToken
}

type sentOTP struct {
	phone string
	code  string
}

type linkToken struct {
	phone string
	token string
}

func (b *fakeOTPBot) GetTelegramStatus(ctx context.Context, phone string) (otpbot.Status, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.statusErr != nil {
		return otpbot.Status{}, b.statusErr
	}
	return b.status, nil
}

func (b *fakeOTPBot) RegisterLinkToken(ctx context.Context, phone, token string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.links = append(b.links, linkToken{phone: phone, token: token})
	return b.linkErr
}

func (b *fakeOTPBot) SendOTP(ctx context.Context, phone, code string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, sentOTP{phone: phone, code: code})
	return b.sendErr
}

func (b *fakeOTPBot) lastSent() (sentOTP, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sent) == 0 {
		return sentOTP{}, false
	}
	return b.sent[len(b.sent)-1], true
}

func TestAuthServiceRequestOTP_SendsViaOTPBot(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	otpBot := &fakeOTPBot{status: otpbot.Status{Linked: true}}
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthService(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, otpBot, nil, time.Minute, time.Hour, 5*time.Minute)

	result, err := service.RequestOTP(context.Background(), "+79991234567")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected no link request, got %#v", result)
	}
	sent, ok := otpBot.lastSent()
	if !ok {
		t.Fatal("expected otp to be sent")
	}
	if sent.phone != "+79991234567" {
		t.Fatalf("expected phone +79991234567, got %s", sent.phone)
	}
	if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(sent.code) {
		t.Fatalf("expected 6 digit code, got %q", sent.code)
	}
	entry := otpRepo.entries["+79991234567"]
	if entry == nil {
		t.Fatal("expected otp to be stored")
	}
	if entry.hash == sent.code {
		t.Fatal("otp stored in plaintext")
	}
	if entry.attemptsLeft != otpMaxAttempts {
		t.Fatalf("expected attempts_left %d, got %d", otpMaxAttempts, entry.attemptsLeft)
	}
}

func TestAuthServiceRequestOTP_TelegramNotLinked(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	otpBot := &fakeOTPBot{status: otpbot.Status{Linked: false}}
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthService(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, otpBot, nil, time.Minute, time.Hour, 5*time.Minute)

	result, err := service.RequestOTP(context.Background(), "+79991234567")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || !result.NeedLink || result.TelegramToken == "" {
		t.Fatalf("expected link token, got %#v", result)
	}
	if _, ok := otpBot.lastSent(); ok {
		t.Fatal("did not expect otp to be sent")
	}
	if _, ok := otpRepo.entries["+79991234567"]; ok {
		t.Fatal("did not expect otp to be stored")
	}
	if len(otpBot.links) != 1 {
		t.Fatalf("expected link token to be registered, got %d", len(otpBot.links))
	}
	if otpBot.links[0].token != result.TelegramToken {
		t.Fatalf("expected token %s, got %s", result.TelegramToken, otpBot.links[0].token)
	}
}

func TestAuthServiceRequestOTP_OTPBotFailure(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	otpBot := &fakeOTPBot{
		status:  otpbot.Status{Linked: true},
		sendErr: otpbot.ErrDeliveryFailed,
	}
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthService(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, otpBot, nil, time.Minute, time.Hour, 5*time.Minute)

	result, err := service.RequestOTP(context.Background(), "+79991234567")
	if err == nil || !common.Is(err, common.CodeDeliveryFailed) {
		t.Fatalf("expected delivery_failed error, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected no link request, got %#v", result)
	}
	if _, ok := otpBot.lastSent(); !ok {
		t.Fatal("expected otp send attempt")
	}
	if _, ok := otpRepo.entries["+79991234567"]; ok {
		t.Fatal("expected otp to be invalidated on send failure")
	}
}

func TestAuthServiceVerifyOTP_Success(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	otpBot := &fakeOTPBot{status: otpbot.Status{Linked: true}}
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthService(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, otpBot, nil, time.Minute, time.Hour, 5*time.Minute)

	phone := "+79991234567"
	result, err := service.RequestOTP(context.Background(), phone)
	if err != nil {
		t.Fatalf("request otp failed: %v", err)
	}
	if result != nil {
		t.Fatalf("expected no link request, got %#v", result)
	}
	sent, ok := otpBot.lastSent()
	if !ok {
		t.Fatal("expected otp to be sent")
	}
	pair, account, isNewUser, err := service.VerifyOTP(context.Background(), phone, sent.code)
	if err != nil {
		t.Fatalf("verify otp failed: %v", err)
	}
	if pair == nil || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected token pair to be issued")
	}
	if account == nil {
		t.Fatal("expected account to be returned")
	}
	if !isNewUser {
		t.Fatal("expected isNewUser to be true")
	}
	if len(account.Roles) != 0 {
		t.Fatalf("expected no role to be set, got %#v", account.Roles)
	}
	if _, ok := otpRepo.entries[phone]; ok {
		t.Fatal("expected otp to be invalidated after success")
	}
	if len(refreshRepo.tokens) == 0 {
		t.Fatal("expected refresh token to be stored")
	}
}

func TestAuthServiceVerifyOTP_Expired(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthService(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, &fakeOTPBot{}, nil, time.Minute, time.Hour, 5*time.Minute)

	phone := "+79991234567"
	otpRepo.entries[phone] = &otpEntry{
		hash:         hashOTP("123456"),
		expiresAt:    time.Now().UTC().Add(-time.Minute).Unix(),
		attemptsLeft: otpMaxAttempts,
		requestedAt:  time.Now().UTC().Add(-time.Minute).Unix(),
	}
	_, _, _, err := service.VerifyOTP(context.Background(), phone, "123456")
	if err == nil || !common.Is(err, common.CodeUnauthorized) {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
	if _, ok := otpRepo.entries[phone]; ok {
		t.Fatal("expected otp to be invalidated on expiry")
	}
}

func TestAuthServiceVerifyOTP_AttemptsExceeded(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthService(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, &fakeOTPBot{}, nil, time.Minute, time.Hour, 5*time.Minute)

	phone := "+79991234567"
	otpRepo.entries[phone] = &otpEntry{
		hash:         hashOTP("111111"),
		expiresAt:    time.Now().UTC().Add(time.Minute).Unix(),
		attemptsLeft: 2,
		requestedAt:  time.Now().UTC().Unix(),
	}
	_, _, _, err := service.VerifyOTP(context.Background(), phone, "000000")
	if err == nil || !common.Is(err, common.CodeUnauthorized) {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
	if entry := otpRepo.entries[phone]; entry == nil || entry.attemptsLeft != 1 {
		t.Fatalf("expected attempts_left 1, got %#v", entry)
	}
	_, _, _, err = service.VerifyOTP(context.Background(), phone, "000000")
	if err == nil || !common.Is(err, common.CodeUnauthorized) {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
	if _, ok := otpRepo.entries[phone]; ok {
		t.Fatal("expected otp to be invalidated after attempts")
	}
}

func TestAuthServiceRequestOTPByTelegram(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	linkRepo := newFakeTelegramLinkRepo()
	linkRepo.links[42] = &telegram.Link{ChatID: 42, Phone: "+79991234567", UserID: "user-1"}
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthServiceWithTelegramLinks(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, nil, linkRepo, nil, time.Minute, time.Hour, 5*time.Minute)

	result, err := service.RequestOTPByTelegram(context.Background(), 42)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || result.Code == "" {
		t.Fatalf("expected otp code, got %#v", result)
	}
	if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(result.Code) {
		t.Fatalf("expected 6 digit code, got %q", result.Code)
	}
	if otpRepo.entries["+79991234567"] == nil {
		t.Fatal("expected otp to be stored")
	}
}

func TestAuthServiceVerifyOTPByTelegram(t *testing.T) {
	otpRepo := newFakeOTPRepo()
	userRepo := newFakeUserRepo()
	refreshRepo := newFakeRefreshTokenRepo()
	linkRepo := newFakeTelegramLinkRepo()
	linkRepo.links[7] = &telegram.Link{ChatID: 7, Phone: "+79990000000", UserID: "user-1"}
	jwtProvider := security.NewJWTProvider("secret")
	service := NewAuthServiceWithTelegramLinks(userRepo, otpRepo, refreshRepo, noopAnalyticsRepo{}, jwtProvider, nil, linkRepo, nil, time.Minute, time.Hour, 5*time.Minute)

	req, err := service.RequestOTPByTelegram(context.Background(), 7)
	if err != nil {
		t.Fatalf("request otp failed: %v", err)
	}
	pair, _, _, err := service.VerifyOTPByTelegram(context.Background(), 7, req.Code)
	if err != nil {
		t.Fatalf("verify otp failed: %v", err)
	}
	if pair == nil || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected token pair to be issued")
	}
}

func hashOTP(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
