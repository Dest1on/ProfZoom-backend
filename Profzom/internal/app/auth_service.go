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
	linkCodePrefix = "PZ-"
	linkCodeLength = 8
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

type RegistrationResult struct {
	UserID   common.UUID
	LinkCode string
}

func (s *AuthService) Register(ctx context.Context) (*RegistrationResult, error) {
	account, err := s.users.Create(ctx, "")
	if err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.registered", UserID: &account.ID, Payload: analyticsPayload(ctx, map[string]string{"user_id": account.ID.String()})})
	if s.otpBot == nil {
		return nil, common.NewError(common.CodeInternal, "otp bot client not configured", nil)
	}
	code, err := generateLinkCode()
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to generate link code", err)
	}
	if err := s.otpBot.RegisterLinkToken(ctx, account.ID.String(), code); err != nil {
		return nil, s.handleOTPBotError(err, account.ID, "link")
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.telegram_link_requested", UserID: &account.ID, Payload: analyticsPayload(ctx, map[string]string{"user_id": account.ID.String()})})
	return &RegistrationResult{UserID: account.ID, LinkCode: code}, nil
}

type OTPRequestPayload struct {
	Code      string
	ExpiresAt time.Time
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
	userID := strings.TrimSpace(link.UserID)
	if userID == "" {
		return nil, common.NewError(common.CodeTelegramNotLinked, "telegram not linked", nil)
	}
	if err := s.otp.DeleteExpired(ctx, time.Now().UTC().Unix()); err != nil {
		return nil, err
	}
	parsedID, err := common.ParseUUID(userID)
	if err != nil {
		return nil, common.NewError(common.CodeValidation, "invalid user_id", err)
	}
	account, err := s.users.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	s.logInfo(fmt.Sprintf("otp request started user_id=%s", account.ID))
	state, err := s.otp.GetState(ctx, userID)
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
	if err := s.otp.UpsertCode(ctx, userID, code, expiresAt.Unix(), otpMaxAttempts); err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.otp_requested", UserID: &account.ID, Payload: analyticsPayload(ctx, map[string]string{"user_id": account.ID.String()})})
	return &OTPRequestPayload{Code: code, ExpiresAt: expiresAt}, nil
}

func (s *AuthService) VerifyOTP(ctx context.Context, userID, code, role string) (*auth.TokenPair, *user.User, bool, error) {
	ok, err := s.otp.VerifyCode(ctx, userID, code, time.Now().UTC().Unix())
	if err != nil {
		return nil, nil, false, err
	}
	if !ok {
		s.logInfo(fmt.Sprintf("otp verification failed user_id=%s", userID))
		_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.otp_failed", Payload: analyticsPayload(ctx, map[string]string{"user_id": userID})})
		return nil, nil, false, common.NewError(common.CodeUnauthorized, "invalid otp code", nil)
	}
	if err := s.otp.InvalidateCode(ctx, userID); err != nil {
		return nil, nil, false, err
	}
	parsedID, err := common.ParseUUID(userID)
	if err != nil {
		return nil, nil, false, common.NewError(common.CodeValidation, "invalid user_id", err)
	}
	account, err := s.users.GetByID(ctx, parsedID)
	if err != nil {
		return nil, nil, false, err
	}
	isNewUser := len(account.Roles) == 0
	var activeRole user.Role
	if isNewUser {
		normalized, err := normalizeRoleValue(role)
		if err != nil {
			return nil, nil, false, err
		}
		if err := s.users.SetRoles(ctx, account.ID, []user.Role{normalized}); err != nil {
			return nil, nil, false, err
		}
		account.Roles = []user.Role{normalized}
		activeRole = normalized
		_ = s.analytics.Create(ctx, analytics.Event{Name: "user.role_selected", UserID: &account.ID, Payload: analyticsPayload(ctx, map[string]string{"role": string(normalized)})})
	} else {
		trimmedRole := strings.TrimSpace(role)
		if trimmedRole != "" {
			normalized, err := normalizeRoleValue(trimmedRole)
			if err != nil {
				return nil, nil, false, err
			}
			hasRole := false
			for _, existing := range account.Roles {
				if existing == normalized {
					hasRole = true
					break
				}
			}
			if !hasRole {
				updatedRoles := append(account.Roles, normalized)
				if err := s.users.SetRoles(ctx, account.ID, updatedRoles); err != nil {
					return nil, nil, false, err
				}
				account.Roles = updatedRoles
				_ = s.analytics.Create(ctx, analytics.Event{Name: "user.role_added", UserID: &account.ID, Payload: analyticsPayload(ctx, map[string]string{"role": string(normalized)})})
			}
			activeRole = normalized
		} else {
			activeRole, err = normalizeRoleSelection(role, account.Roles)
			if err != nil {
				return nil, nil, false, err
			}
		}
	}
	pair, err := s.issueTokens(ctx, account, activeRole)
	if err != nil {
		return nil, nil, false, err
	}
	payload := map[string]string{"user_id": account.ID.String()}
	if activeRole != "" {
		payload["role"] = string(activeRole)
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.otp_verified", UserID: &account.ID, Payload: analyticsPayload(ctx, payload)})
	_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.logged_in", UserID: &account.ID, Payload: analyticsPayload(ctx, payload)})
	s.logInfo(fmt.Sprintf("user logged in user_id=%s", account.ID))
	return pair, account, isNewUser, nil
}

func (s *AuthService) VerifyOTPByTelegram(ctx context.Context, chatID int64, code, role string) (*auth.TokenPair, *user.User, bool, error) {
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
	userID := strings.TrimSpace(link.UserID)
	if userID == "" {
		return nil, nil, false, common.NewError(common.CodeTelegramNotLinked, "telegram not linked", nil)
	}
	return s.VerifyOTP(ctx, userID, code, role)
}

func (s *AuthService) Refresh(ctx context.Context, token, role string) (*auth.TokenPair, *user.User, error) {
	stored, err := s.refreshTokens.GetByToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}
	if stored.RevokedAt != nil {
		return nil, nil, common.NewError(common.CodeUnauthorized, "refresh token revoked", nil)
	}
	if stored.ExpiresAt.Before(time.Now().UTC()) {
		return nil, nil, common.NewError(common.CodeUnauthorized, "refresh token expired", nil)
	}
	account, err := s.users.GetByID(ctx, stored.UserID)
	if err != nil {
		return nil, nil, err
	}
	requestedRole := strings.TrimSpace(role)
	activeRole := strings.TrimSpace(stored.Role)
	if requestedRole != "" {
		activeRole = requestedRole
	}
	normalizedRole, err := normalizeRoleSelection(activeRole, account.Roles)
	if err != nil {
		return nil, nil, err
	}
	if err := s.refreshTokens.Revoke(ctx, token, time.Now().UTC().Unix()); err != nil {
		return nil, nil, err
	}
	pair, err := s.issueTokens(ctx, account, normalizedRole)
	if err != nil {
		return nil, nil, err
	}
	payload := map[string]string{"user_id": account.ID.String()}
	if normalizedRole != "" {
		payload["role"] = string(normalizedRole)
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.token_refreshed", UserID: &account.ID, Payload: analyticsPayload(ctx, payload)})
	return pair, account, nil
}

func (s *AuthService) Logout(ctx context.Context, token string) error {
	err := s.refreshTokens.Revoke(ctx, token, time.Now().UTC().Unix())
	if err == nil {
		s.logInfo("user logged out")
		_ = s.analytics.Create(ctx, analytics.Event{Name: "auth.logged_out", Payload: analyticsPayload(ctx, nil)})
	}
	return err
}

func (s *AuthService) issueTokens(ctx context.Context, account *user.User, activeRole user.Role) (*auth.TokenPair, error) {
	roles := make([]string, len(account.Roles))
	for i, role := range account.Roles {
		roles[i] = string(role)
	}
	selectedRole := string(activeRole)
	if selectedRole == "" && len(account.Roles) == 1 {
		selectedRole = string(account.Roles[0])
	}
	accessToken, expiresAt, err := s.jwtProvider.Generate(account.ID, roles, selectedRole, s.accessTTL)
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
		Role:      selectedRole,
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

func generateLinkCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	max := big.NewInt(int64(len(alphabet)))
	code := make([]byte, linkCodeLength)
	for i := range code {
		value, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		code[i] = alphabet[value.Int64()]
	}
	return linkCodePrefix + string(code), nil
}

func normalizeRoleSelection(value string, roles []user.Role) (user.Role, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		if len(roles) == 1 {
			return roles[0], nil
		}
		if len(roles) > 1 {
			return "", common.NewValidationError("invalid role", map[string]string{"role": "role is required when multiple roles are assigned"})
		}
		return "", nil
	}
	normalized := user.Role(strings.ToLower(trimmed))
	if normalized != user.RoleStudent && normalized != user.RoleCompany {
		return "", common.NewValidationError("invalid role", map[string]string{"role": "role must be student or company"})
	}
	for _, role := range roles {
		if role == normalized {
			return normalized, nil
		}
	}
	return "", common.NewValidationError("invalid role", map[string]string{"role": "role not assigned to user"})
}

func normalizeRoleValue(value string) (user.Role, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", common.NewValidationError("invalid role", map[string]string{"role": "role is required"})
	}
	normalized := user.Role(strings.ToLower(trimmed))
	if normalized != user.RoleStudent && normalized != user.RoleCompany {
		return "", common.NewValidationError("invalid role", map[string]string{"role": "role must be student or company"})
	}
	return normalized, nil
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
