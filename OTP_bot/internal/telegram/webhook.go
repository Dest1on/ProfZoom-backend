package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"otp_bot/internal/observability"
)

const (
	telegramSecretHeader = "X-Telegram-Bot-Api-Secret-Token"
	linkCodePrefix       = "PZ-"
)

var otpCodePattern = regexp.MustCompile(`^[0-9]{6}$`)

// Update представляет payload обновления Telegram для доставки через webhook.
type Update struct {
	UpdateID int64    `json:"update_id"`
	Message  *Message `json:"message,omitempty"`
}

type Message struct {
	MessageID int64    `json:"message_id"`
	Chat      Chat     `json:"chat"`
	Text      string   `json:"text"`
	From      User     `json:"from"`
	Contact   *Contact `json:"contact,omitempty"`
}

type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type Contact struct {
	PhoneNumber string `json:"phone_number"`
	UserID      int64  `json:"user_id,omitempty"`
}

// ErrInvalidToken сообщает, что токен верификации неверный или истек.
var ErrInvalidToken = errors.New("verification token invalid or expired")

// ErrLinkNotFound сообщает об отсутствии привязки Telegram.
var ErrLinkNotFound = errors.New("telegram link not found")
var ErrAlreadyLinked = errors.New("telegram already linked")

// VerificationService проверяет токен верификации и привязывает чат Telegram.
type VerificationService interface {
	VerifyAndLink(ctx context.Context, token string, chatID int64) (LinkResult, error)
}

type RateLimiter interface {
	Allow(key string) bool
}

// LinkResult описывает результат привязки чата.
type LinkResult struct {
	UserID string
	Phone  string
}

// LinkInfo описывает связанную пару пользователь-чат.
type LinkInfo struct {
	UserID string
	Phone  string
	ChatID int64
}

// LinkStore управляет связями пользователь-чат для бота.
type LinkStore interface {
	GetByChatID(ctx context.Context, chatID int64) (LinkInfo, error)
}

// Bot обрабатывает входящие обновления Telegram.
type Bot struct {
	sender    Service
	verifier  VerificationService
	linkStore LinkStore
	otpClient OTPClient
	limiter   RateLimiter
	logger    *slog.Logger
}

// NewBot создает обработчик бота Telegram.
func NewBot(sender Service, verifier VerificationService, linkStore LinkStore, otpClient OTPClient, limiter RateLimiter, logger *slog.Logger) *Bot {
	if logger == nil {
		logger = slog.Default()
	}
	return &Bot{
		sender:    sender,
		verifier:  verifier,
		linkStore: linkStore,
		otpClient: otpClient,
		limiter:   limiter,
		logger:    logger,
	}
}

// HandleUpdate маршрутизирует поддерживаемые команды Telegram.
func (b *Bot) HandleUpdate(ctx context.Context, update Update) error {
	if update.Message == nil {
		return nil
	}

	msg := update.Message
	if msg.Chat.ID <= 0 {
		return nil
	}
	if msg.Chat.Type != "" && msg.Chat.Type != "private" {
		return nil
	}
	if b.limiter != nil {
		key := fmt.Sprintf("chat:%d", msg.Chat.ID)
		if !b.limiter.Allow(key) {
			b.logger.Warn("telegram inbound rate limited", slog.Int64("chat_id", msg.Chat.ID))
			return nil
		}
	}

	if msg.Contact != nil {
		return b.handleContact(ctx, msg)
	}

	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return nil
	}
	command, arg := parseCommand(text)
	if strings.HasPrefix(command, "/") {
		switch command {
		case "/start":
			return b.handleStart(ctx, msg, arg)
		case "/help":
			return b.sendHelp(ctx, msg.Chat.ID)
		case "/status":
			return b.handleStatus(ctx, msg.Chat.ID)
		case "/code":
			return b.handleCodeCommand(ctx, msg.Chat.ID, arg)
		default:
			return b.sendMessage(ctx, msg.Chat.ID, "I did not understand. Use /help.", nil)
		}
	}
	if code, ok := normalizeLinkCode(text); ok {
		return b.handleLinkCode(ctx, msg.Chat.ID, code)
	}
	if otpCodePattern.MatchString(text) {
		return b.handleOTPVerification(ctx, msg.Chat.ID, text)
	}
	return b.sendMessage(ctx, msg.Chat.ID, "I did not understand. Send the link code from the app or use /help.", nil)
}

func parseCommand(text string) (string, string) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return "", ""
	}
	command := fields[0]
	if idx := strings.Index(command, "@"); idx != -1 {
		command = command[:idx]
	}
	arg := ""
	if len(fields) > 1 {
		arg = fields[1]
	}
	return command, arg
}

func normalizeLinkCode(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", false
	}
	upper := strings.ToUpper(trimmed)
	if !strings.HasPrefix(upper, linkCodePrefix) {
		return "", false
	}
	if len(upper) <= len(linkCodePrefix) {
		return "", false
	}
	return upper, true
}

func (b *Bot) handleStart(ctx context.Context, message *Message, arg string) error {
	token, ok := normalizeLinkCode(arg)
	if !ok {
		return b.handleStartWithoutToken(ctx, message.Chat.ID)
	}
	return b.handleLinkCode(ctx, message.Chat.ID, token)
}

func (b *Bot) handleLinkCode(ctx context.Context, chatID int64, token string) error {
	if b.linkStore != nil {
		if _, err := b.linkStore.GetByChatID(ctx, chatID); err == nil {
			return b.sendMessage(ctx, chatID, "Your Telegram is already linked. Use /code to receive a login code.", nil)
		} else if !errors.Is(err, ErrLinkNotFound) {
			return err
		}
	}
	if b.verifier == nil {
		return b.sendMessage(ctx, chatID, "Linking is unavailable right now.", nil)
	}
	result, err := b.verifier.VerifyAndLink(ctx, token, chatID)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			b.logger.Info("invalid verification token", slog.Int64("chat_id", chatID))
			return b.sendMessage(ctx, chatID, "Invalid or expired link code. Please request a new one in the app.", nil)
		}
		if errors.Is(err, ErrAlreadyLinked) {
			return b.sendMessage(ctx, chatID, "Your Telegram is already linked. Use /code to receive a login code.", nil)
		}
		b.logger.Error("verification failed", slog.Int64("chat_id", chatID), slog.String("error", err.Error()))
		return fmt.Errorf("telegram verification failed: %w", err)
	}

	b.logger.Info("telegram linked", slog.Int64("chat_id", chatID), slog.String("user_id", result.UserID))
	if b.otpClient != nil {
		if otp, err := b.otpClient.RequestOTP(ctx, chatID); err == nil {
			msg := fmt.Sprintf("Account linked. Your login code: %s. It expires in %s.", otp.Code, formatOTPExpiry(otp.ExpiresAt))
			return b.sendMessage(ctx, chatID, msg, nil)
		}
	}
	return b.sendMessage(ctx, chatID, "Account linked. Use /code to receive a login code.", nil)
}

func (b *Bot) handleStartWithoutToken(ctx context.Context, chatID int64) error {
	if b.linkStore != nil {
		if _, err := b.linkStore.GetByChatID(ctx, chatID); err == nil {
			if b.otpClient != nil {
				return b.handleOTPRequest(ctx, chatID)
			}
			return b.sendMessage(ctx, chatID, "OTP requests are unavailable right now.", nil)
		} else if !errors.Is(err, ErrLinkNotFound) {
			return err
		}
	}
	return b.sendStart(ctx, chatID)
}

func (b *Bot) handleStatus(ctx context.Context, chatID int64) error {
	if b.linkStore == nil {
		return b.sendMessage(ctx, chatID, "Link status is unavailable right now.", nil)
	}

	_, err := b.linkStore.GetByChatID(ctx, chatID)
	if err != nil {
		if errors.Is(err, ErrLinkNotFound) {
			return b.sendMessage(ctx, chatID, "Your Telegram is not linked yet. Send the link code from the app.", nil)
		}
		return err
	}

	return b.sendMessage(ctx, chatID, "Your Telegram is linked.", nil)
}

func (b *Bot) handleCodeCommand(ctx context.Context, chatID int64, arg string) error {
	if b.otpClient == nil {
		return b.sendMessage(ctx, chatID, "OTP requests are unavailable right now.", nil)
	}
	code := strings.TrimSpace(arg)
	if code == "" {
		return b.handleOTPRequest(ctx, chatID)
	}
	if !otpCodePattern.MatchString(code) {
		return b.sendMessage(ctx, chatID, "Invalid code format. Send 6 digits.", nil)
	}
	return b.handleOTPVerification(ctx, chatID, code)
}

func (b *Bot) handleOTPRequest(ctx context.Context, chatID int64) error {
	result, err := b.otpClient.RequestOTP(ctx, chatID)
	if err != nil {
		return b.handleOTPError(ctx, chatID, err)
	}
	message := fmt.Sprintf("Your login code: %s. It expires in %s.", result.Code, formatOTPExpiry(result.ExpiresAt))
	return b.sendMessage(ctx, chatID, message, nil)
}

func (b *Bot) handleOTPVerification(ctx context.Context, chatID int64, code string) error {
	if b.otpClient == nil {
		return b.sendMessage(ctx, chatID, "OTP verification is unavailable right now.", nil)
	}
	if !otpCodePattern.MatchString(code) {
		return b.sendMessage(ctx, chatID, "Invalid code format. Send 6 digits.", nil)
	}
	if _, err := b.otpClient.VerifyOTP(ctx, chatID, code); err != nil {
		return b.handleOTPError(ctx, chatID, err)
	}
	return b.sendMessage(ctx, chatID, "Code verified. You can return to the app to finish login.", nil)
}

func (b *Bot) handleOTPError(ctx context.Context, chatID int64, err error) error {
	switch {
	case errors.Is(err, ErrOTPNotLinked):
		return b.sendMessage(ctx, chatID, "Your Telegram is not linked yet. Send the link code from the app.", nil)
	case errors.Is(err, ErrOTPRateLimited):
		return b.sendMessage(ctx, chatID, "Too many requests. Please wait before trying again.", nil)
	case errors.Is(err, ErrOTPInvalid):
		return b.sendMessage(ctx, chatID, "Invalid or expired code. Request a new one with /code.", nil)
	case errors.Is(err, ErrOTPBadRequest):
		return b.sendMessage(ctx, chatID, "Invalid request. Please try again.", nil)
	case errors.Is(err, ErrOTPUnauthorized):
		return b.sendMessage(ctx, chatID, "OTP service unavailable. Please try again later.", nil)
	default:
		b.logger.Error("otp api error", slog.Int64("chat_id", chatID), slog.String("error", err.Error()))
		return b.sendMessage(ctx, chatID, "OTP request failed. Please try again later.", nil)
	}
}

func (b *Bot) handleContact(ctx context.Context, message *Message) error {
	if message.Contact == nil {
		return nil
	}
	return b.sendMessage(ctx, message.Chat.ID, "Phone linking is no longer supported. Send the link code from the app.", nil)
}

func (b *Bot) sendStart(ctx context.Context, chatID int64) error {
	text := "Hello! I deliver one-time codes for ProfZoom.\n" +
		"To link your account, open the app and get a link code.\n" +
		"Send that code to me, then use /code to receive a login code."
	return b.sendMessage(ctx, chatID, text, nil)
}

func (b *Bot) sendHelp(ctx context.Context, chatID int64) error {
	text := "I send ProfZoom login codes. Send the link code from the app, then use /code to receive a login code."
	return b.sendMessage(ctx, chatID, text, nil)
}

func formatOTPExpiry(expiresAt time.Time) string {
	if expiresAt.IsZero() {
		return "a few minutes"
	}
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return "less than a minute"
	}
	minutes := int(remaining.Minutes())
	if minutes <= 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", minutes)
}

func (b *Bot) contactKeyboard() *ReplyKeyboardMarkup {
	return &ReplyKeyboardMarkup{
		Keyboard: [][]KeyboardButton{{{
			Text:           "Share my phone number",
			RequestContact: true,
		}}},
		ResizeKeyboard:  true,
		OneTimeKeyboard: true,
	}
}

func (b *Bot) sendMessage(ctx context.Context, chatID int64, text string, replyMarkup any) error {
	if replyMarkup != nil {
		if sender, ok := b.sender.(MarkupSender); ok {
			return sender.SendMessageWithMarkup(ctx, chatID, text, replyMarkup)
		}
	}
	return b.sender.SendMessage(ctx, chatID, text)
}

// WebhookHandler проверяет запросы Telegram webhook и передает обновления.
type WebhookHandler struct {
	bot          *Bot
	secretToken  string
	maxBodyBytes int64
	logger       *slog.Logger
}

// NewWebhookHandler создает обработчик webhook, который проверяет секретный токен Telegram.
func NewWebhookHandler(bot *Bot, secretToken string, logger *slog.Logger) *WebhookHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &WebhookHandler{
		bot:          bot,
		secretToken:  secretToken,
		maxBodyBytes: 1 << 20,
		logger:       logger,
	}
}

// ServeHTTP реализует http.Handler для коллбэков Telegram webhook.
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if h.secretToken != "" && r.Header.Get(telegramSecretHeader) != h.secretToken {
		h.logger.Warn("unauthorized webhook request", slog.String("request_id", observability.RequestIDFromContext(r.Context())))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	defer body.Close()

	payload, err := io.ReadAll(body)
	if err != nil {
		h.logger.Warn("failed to read webhook body", slog.String("request_id", observability.RequestIDFromContext(r.Context())))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var update Update
	if err := json.Unmarshal(payload, &update); err != nil {
		h.logger.Warn("invalid webhook payload", slog.String("request_id", observability.RequestIDFromContext(r.Context())))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := h.bot.HandleUpdate(r.Context(), update); err != nil {
		h.logger.Error("failed to handle telegram update", slog.String("request_id", observability.RequestIDFromContext(r.Context())), slog.String("error", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
