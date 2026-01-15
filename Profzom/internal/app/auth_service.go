package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"profzom/internal/common"
	"profzom/internal/domain/analytics"
	"profzom/internal/domain/auth"
	"profzom/internal/domain/telegram"
	"profzom/internal/domain/user"
	"profzom/internal/integration/otpbot"
	"profzom/internal/security"
)

// AuthService предоставляет основную реализацию авторизации, используемую HTTP-обработчиками
type AuthService struct {
	users         user.Repository
	otp           auth.OTPRepository
	refreshTokens auth.RefreshTokenRepository
	analytics     analytics.Repository
	jwtProvider   *security.JWTProvider
	otpBot        otpbot.Client
	telegramLinks telegram.LinkRepository
	logger        Logger
	accessTTL     time.Duration
	refreshTTL    time.Duration
	otpTTL        time.Duration
}

const (
	otpMaxAttempts = 5
	otpMinInterval = 30 * time.Second
	otpCodeLength  = 6
)

type Logger interface {
	Info(msg string)
	Error(msg string)
}

func NewAuthService(users user.Repository, otp auth.OTPRepository, refreshTokens auth.RefreshTokenRepository, analytics analytics.Repository, jwtProvider *security.JWTProvider, otpBot otpbot.Client, logger Logger, accessTTL, refreshTTL, otpTTL time.Duration) *AuthService {
	return &AuthService{
		users:         users,
		otp:           otp,
		refreshTokens: refreshTokens,
		analytics:     analytics,
		jwtProvider:   jwtProvider,
		otpBot:        otpBot,
		telegramLinks: nil,
		logger:        logger,
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
		otpTTL:        otpTTL,
	}
}

func NewAuthServiceWithTelegramLinks(users user.Repository, otp auth.OTPRepository, refreshTokens auth.RefreshTokenRepository, analytics analytics.Repository, jwtProvider *security.JWTProvider, otpBot otpbot.Client, telegramLinks telegram.LinkRepository, logger Logger, accessTTL, refreshTTL, otpTTL time.Duration) *AuthService {
	service := NewAuthService(users, otp, refreshTokens, analytics, jwtProvider, otpBot, logger, accessTTL, refreshTTL, otpTTL)
	service.telegramLinks = telegramLinks
	return service
}

type OTPRequestResult struct {
	NeedLink      bool
	TelegramToken string
}

func (s *AuthService) RequestOTP(ctx context.Context, phone string) (*OTPRequestResult, error) {
	if err := s.otp.DeleteExpired(ctx, time.Now().UTC().Unix()); err != nil {
		return nil, err
	}
	account, err := s.loadOrCreateUser(ctx, phone)
	if err != nil {
		return nil, err
	}
	s.logInfo(fmt.Sprintf("otp request started user_id=%s", account.ID))
	state, err := s.otp.GetState(ctx, phone)
	if err != nil {
		return nil, err
	}
	if state != nil {
		requestedAt := time.Unix(state.RequestedAt, 0).UTC()
		if time.Since(requestedAt) < otpMinInterval {
			return nil, common.NewError(common.CodeValidation, "otp requested too frequently", nil)
		}
	}
	if s.otpBot == nil {
		return nil, common.NewError(common.CodeInternal, "otp bot client not configured", nil)
	}
	status, err := s.otpBot.GetTelegramStatus(ctx, phone)
	if err != nil {
		return nil, s.handleOTPBotError(err, account.ID, "status")
	}
	if !status.Linked {
		result, linkErr := s.startTelegramLink(ctx, account.ID, phone)
		if linkErr != nil {
			return nil, linkErr
		}
		return result, nil
	}
	code, err := generateOTP()
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to generate otp", err)
	}
	expiresAt := time.Now().UTC().Add(s.otpTTL).Unix()
	if err := s.otp.UpsertCode(ctx, phone, code, expiresAt, otpMaxAttempts); err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.otp_requested", Payload: analyticsPayload(ctx, map[string]string{"phone": phone})})
	if err := s.otpBot.SendOTP(ctx, phone, code); err != nil {
		_ = s.otp.InvalidateCode(ctx, phone)
		if errors.Is(err, otpbot.ErrNotLinked) {
			result, linkErr := s.startTelegramLink(ctx, account.ID, phone)
			if linkErr == nil {
				return result, nil
			}
			return nil, linkErr
		}
		return nil, s.handleOTPBotError(err, account.ID, "send")
	}
	return nil, nil
}

type OTPRequestPayload struct {
	Code      string
	ExpiresAt time.Time
	Phone     string
}

func (s *AuthService) RequestOTPByTelegram(ctx context.Context, chatID int64) (*OTPRequestPayload, error) {
	if s.telegramLinks == nil {
		return nil, common.NewError(common.CodeInternal, "telegram link repository not configured", nil)
	}
	link, err := s.telegramLinks.GetByChatID(ctx, chatID)
	if err != nil {
		if common.Is(err, common.CodeNotFound) {
			return nil, common.NewError(common.CodeTelegramNotLinked, "telegram not linked", nil)
		}
		return nil, err
	}
	if link.Phone == "" {
		return nil, common.NewError(common.CodeTelegramNotLinked, "telegram not linked", nil)
	}
	if err := s.otp.DeleteExpired(ctx, time.Now().UTC().Unix()); err != nil {
		return nil, err
	}
	account, err := s.loadOrCreateUser(ctx, link.Phone)
	if err != nil {
		return nil, err
	}
	s.logInfo(fmt.Sprintf("otp request started user_id=%s", account.ID))
	state, err := s.otp.GetState(ctx, link.Phone)
	if err != nil {
		return nil, err
	}
	if state != nil {
		requestedAt := time.Unix(state.RequestedAt, 0).UTC()
		if time.Since(requestedAt) < otpMinInterval {
			return nil, common.NewError(common.CodeValidation, "otp requested too frequently", nil)
		}
	}
	code, err := generateOTP()
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to generate otp", err)
	}
	expiresAt := time.Now().UTC().Add(s.otpTTL)
	if err := s.otp.UpsertCode(ctx, link.Phone, code, expiresAt.Unix(), otpMaxAttempts); err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.otp_requested", Payload: analyticsPayload(ctx, map[string]string{"phone": link.Phone})})
	return &OTPRequestPayload{Code: code, ExpiresAt: expiresAt, Phone: link.Phone}, nil
}

func (s *AuthService) VerifyOTP(ctx context.Context, phone, code string) (*auth.TokenPair, *user.User, bool, error) {
	ok, err := s.otp.VerifyCode(ctx, phone, code, time.Now().UTC().Unix())
	if err != nil {
		return nil, nil, false, err
	}
	if !ok {
		s.logInfo(fmt.Sprintf("otp verification failed phone=%s", maskPhone(phone)))
		_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.otp_failed", Payload: analyticsPayload(ctx, map[string]string{"phone": phone})})
		return nil, nil, false, common.NewError(common.CodeUnauthorized, "invalid otp code", nil)
	}
	if err := s.otp.InvalidateCode(ctx, phone); err != nil {
		return nil, nil, false, err
	}
	account, err := s.users.FindByPhone(ctx, phone)
	if err != nil {
		return nil, nil, false, err
	}
	isNewUser := len(account.Roles) == 0
	pair, err := s.issueTokens(ctx, account)
	if err != nil {
		return nil, nil, false, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.logged_in", UserID: &account.ID, Payload: analyticsPayload(ctx, map[string]string{"user_id": account.ID.String()})})
	s.logInfo(fmt.Sprintf("user logged in user_id=%s", account.ID))
	return pair, account, isNewUser, nil
}

func (s *AuthService) VerifyOTPByTelegram(ctx context.Context, chatID int64, code string) (*auth.TokenPair, *user.User, bool, error) {
	if s.telegramLinks == nil {
		return nil, nil, false, common.NewError(common.CodeInternal, "telegram link repository not configured", nil)
	}
	link, err := s.telegramLinks.GetByChatID(ctx, chatID)
	if err != nil {
		if common.Is(err, common.CodeNotFound) {
			return nil, nil, false, common.NewError(common.CodeTelegramNotLinked, "telegram not linked", nil)
		}
		return nil, nil, false, err
	}
	if link.Phone == "" {
		return nil, nil, false, common.NewError(common.CodeTelegramNotLinked, "telegram not linked", nil)
	}
	return s.VerifyOTP(ctx, link.Phone, code)
}

func (s *AuthService) Refresh(ctx context.Context, token string) (*auth.TokenPair, error) {
	stored, err := s.refreshTokens.GetByToken(ctx, token)
	if err != nil {
		return nil, err
	}
	if stored.RevokedAt != nil {
		return nil, common.NewError(common.CodeUnauthorized, "refresh token revoked", nil)
	}
	if stored.ExpiresAt.Before(time.Now().UTC()) {
		return nil, common.NewError(common.CodeUnauthorized, "refresh token expired", nil)
	}
	account, err := s.users.GetByID(ctx, stored.UserID)
	if err != nil {
		return nil, err
	}
	if err := s.refreshTokens.Revoke(ctx, token, time.Now().UTC().Unix()); err != nil {
		return nil, err
	}
	return s.issueTokens(ctx, account)
}

func (s *AuthService) Logout(ctx context.Context, token string) error {
	err := s.refreshTokens.Revoke(ctx, token, time.Now().UTC().Unix())
	if err == nil {
		s.logInfo("user logged out")
	}
	return err
}

func (s *AuthService) issueTokens(ctx context.Context, account *user.User) (*auth.TokenPair, error) {
	roles := make([]string, len(account.Roles))
	for i, role := range account.Roles {
		roles[i] = string(role)
	}
	accessToken, expiresAt, err := s.jwtProvider.Generate(account.ID, roles, s.accessTTL)
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to generate access token", err)
	}
	refreshValue, err := generateRefreshToken()
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to generate refresh token", err)
	}
	refresh := auth.RefreshToken{
		ID:        common.NewUUID(),
		UserID:    account.ID,
		Token:     refreshValue,
		ExpiresAt: time.Now().UTC().Add(s.refreshTTL),
		CreatedAt: time.Now().UTC(),
	}
	if err := s.refreshTokens.Store(ctx, refresh); err != nil {
		return nil, err
	}
	return &auth.TokenPair{AccessToken: accessToken, RefreshToken: refreshValue, ExpiresAt: expiresAt}, nil
}

func generateOTP() (string, error) {
	max := big.NewInt(0).Exp(big.NewInt(10), big.NewInt(otpCodeLength), nil)
	value, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	format := fmt.Sprintf("%%0%dd", otpCodeLength)
	return fmt.Sprintf(format, value.Int64()), nil
}

func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func generateTelegramLinkToken() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func maskPhone(phone string) string {
	trimmed := strings.TrimSpace(phone)
	if trimmed == "" {
		return ""
	}
	prefix := ""
	if strings.HasPrefix(trimmed, "+") {
		prefix = "+"
		trimmed = strings.TrimPrefix(trimmed, "+")
	}
	if len(trimmed) <= 4 {
		return prefix + strings.Repeat("*", len(trimmed))
	}
	return prefix + strings.Repeat("*", len(trimmed)-4) + trimmed[len(trimmed)-4:]
}

func (s *AuthService) loadOrCreateUser(ctx context.Context, phone string) (*user.User, error) {
	account, err := s.users.FindByPhone(ctx, phone)
	if err != nil {
		if common.Is(err, common.CodeNotFound) {
			account, err = s.users.Create(ctx, phone)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return account, nil
}

func (s *AuthService) logInfo(msg string) {
	if s.logger == nil {
		return
	}
	s.logger.Info(msg)
}

func (s *AuthService) logError(msg string) {
	if s.logger == nil {
		return
	}
	s.logger.Error(msg)
}

func (s *AuthService) startTelegramLink(ctx context.Context, userID common.UUID, phone string) (*OTPRequestResult, error) {
	token, err := generateTelegramLinkToken()
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to generate telegram link token", err)
	}
	if err := s.otpBot.RegisterLinkToken(ctx, phone, token); err != nil {
		return nil, s.handleOTPBotError(err, userID, "link")
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.telegram_link_requested", Payload: analyticsPayload(ctx, map[string]string{"phone": phone})})
	return &OTPRequestResult{NeedLink: true, TelegramToken: token}, nil
}

func (s *AuthService) handleOTPBotError(err error, userID common.UUID, stage string) error {
	switch {
	case errors.Is(err, otpbot.ErrUnauthorized):
		s.logError(fmt.Sprintf("otp bot unauthorized stage=%s user_id=%s", stage, userID))
		return common.NewError(common.CodeInternal, "otp bot unauthorized", err)
	case errors.Is(err, otpbot.ErrNotLinked):
		s.logInfo(fmt.Sprintf("otp request refused telegram not linked user_id=%s", userID))
		return common.NewError(common.CodeTelegramNotLinked, "telegram not linked", nil)
	case errors.Is(err, otpbot.ErrBadRequest):
		s.logError(fmt.Sprintf("otp bot bad request stage=%s user_id=%s", stage, userID))
		return common.NewError(common.CodeValidation, "invalid request", err)
	case errors.Is(err, otpbot.ErrRateLimited):
		s.logError(fmt.Sprintf("otp bot rate limited stage=%s user_id=%s", stage, userID))
		return common.NewError(common.CodeRateLimited, "otp bot rate limited", nil)
	case errors.Is(err, otpbot.ErrDeliveryFailed):
		s.logError(fmt.Sprintf("otp delivery failed stage=%s user_id=%s", stage, userID))
		return common.NewError(common.CodeDeliveryFailed, "otp delivery failed", nil)
	default:
		s.logError(fmt.Sprintf("otp bot error stage=%s user_id=%s", stage, userID))
		return common.NewError(common.CodeInternal, "otp bot error", err)
	}
}
