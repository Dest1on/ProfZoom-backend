package otpbot

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"otp_bot/internal/config"
	"otp_bot/internal/httpapi"
	"otp_bot/internal/integration/profzom"
	"otp_bot/internal/linking"
	"otp_bot/internal/logging"
	"otp_bot/internal/observability"
	"otp_bot/internal/ratelimit"
	"otp_bot/internal/store/postgres"
	"otp_bot/internal/telegram"
)

// Run запускает сервис OTP бота и блокирует выполнение до остановки.
func Run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := logging.NewLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	telegramClient := telegram.NewClient(cfg.BotToken, &http.Client{Timeout: cfg.TelegramTimeout})
	apiClient := profzom.NewClient(cfg.APIBaseURL, cfg.APIInternalKey, &http.Client{Timeout: cfg.APITimeout})

	var db *sql.DB
	var linkStore linking.TelegramLinkStore
	var linkTokenStore linking.LinkTokenStore

	if cfg.DatabaseURL == "" {
		logger.Warn("database url missing, using in-memory stores")
		linkStore = linking.NewMemoryTelegramLinkStore()
		linkTokenStore = linking.NewMemoryLinkTokenStore()
	} else {
		db, err = sql.Open(cfg.DBDriver, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("database connect failed: %w", err)
		}
		defer db.Close()
		linkStore = postgres.NewTelegramLinkStore(db)
		linkTokenStore = postgres.NewTelegramLinkTokenStore(db)
	}
	hashSecret := []byte(cfg.InternalAuthKey)

	linker := linking.NewTelegramLinker(linkTokenStore, linkStore, hashSecret)
	linkRegistrar := linking.NewLinkTokenRegistrar(linkTokenStore, cfg.LinkTokenTTL, hashSecret)
	botLinkStore := linking.NewBotLinkStore(linkStore)
	bot := telegram.NewBot(telegramClient, linker, botLinkStore, apiClient, logger)
	webhookHandler := telegram.NewWebhookHandler(bot, cfg.WebhookSecret, logger)

	otpPerChatLimiter := ratelimit.NewMemoryLimiter(cfg.OTPSendPerMin, time.Minute)
	otpPerIPLimiter := ratelimit.NewMemoryLimiter(cfg.OTPSendIPPerMin, time.Minute)
	otpBotLimiter := ratelimit.NewMemoryLimiter(cfg.OTPSendBotPerMin, time.Minute)
	otpHandler := httpapi.NewOTPHandler(telegramClient, cfg.InternalAuthKey, linkStore, otpPerChatLimiter, otpPerIPLimiter, otpBotLimiter, logger)

	linkTokenIPLimiter := ratelimit.NewMemoryLimiter(cfg.LinkTokenRateLimitIPPerMin, time.Minute)
	linkTokenBotLimiter := ratelimit.NewMemoryLimiter(cfg.LinkTokenRateLimitBotPerMin, time.Minute)
	api := httpapi.NewAPI(linkRegistrar, linkStore, cfg.InternalAuthKey, linkTokenIPLimiter, linkTokenBotLimiter, logger)

	mux := http.NewServeMux()
	mux.Handle("/telegram/webhook", webhookHandler)
	mux.HandleFunc("/telegram/link-token", api.HandleLinkToken)
	mux.HandleFunc("/telegram/status", api.HandleStatus)
	mux.Handle("/otp/send", otpHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           withRequestID(logger, mux),
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("otp bot listening", slog.String("port", cfg.Port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("otp bot server error", slog.String("error", err.Error()))
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("otp bot shutdown error", slog.String("error", err.Error()))
	}

	return nil
}

func withRequestID(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = observability.NewRequestID()
		}
		ctx := observability.WithRequestID(r.Context(), requestID)
		w.Header().Set("X-Request-ID", requestID)
		logger.Debug("request received", slog.String("path", r.URL.Path), slog.String("method", r.Method), slog.String("request_id", requestID))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
