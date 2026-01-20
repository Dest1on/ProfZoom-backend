package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config хранит конфигурацию времени выполнения для сервиса OTP бота.
type Config struct {
	BotToken                    string
	TelegramWebhookURL          string
	TelegramWebhookDropPending  bool
	WebhookSecret               string
	InternalAuthKey             string
	APIBaseURL                  string
	APIInternalKey              string
	DatabaseURL                 string
	RedisURL                    string
	DBDriver                    string
	Port                        string
	LogLevel                    string
	TelegramTimeout             time.Duration
	TelegramPollingEnabled      bool
	TelegramPollingTimeout      time.Duration
	TelegramPollingInterval     time.Duration
	TelegramPollingLimit        int
	TelegramPollingDropPending  bool
	TelegramPollingDropWebhook  bool
	TelegramInboundRateLimit    int
	APITimeout                  time.Duration
	OTPSendPerMin               int
	OTPSendIPPerMin             int
	OTPSendBotPerMin            int
	LinkTokenTTL                time.Duration
	LinkTokenRateLimitPerMin    int
	LinkTokenRateLimitIPPerMin  int
	LinkTokenRateLimitBotPerMin int
}

// Load читает конфигурацию из переменных окружения.
func Load() (Config, error) {
	otpPerMin := intOr("OTP_RATE_LIMIT_PER_MIN", 2)
	otpBotPerMin := intOr("OTP_RATE_LIMIT_BOT_PER_MIN", 60)
	linkTokenPerMin := intOr("LINK_TOKEN_RATE_LIMIT_PER_MIN", 5)
	pollingEnabled := boolOr("TELEGRAM_POLLING_ENABLED", false)
	inboundRate := intOr("TELEGRAM_INBOUND_RATE_LIMIT_PER_MIN", 30)

	cfg := Config{
		Port:                        envOr("PORT", "8080"),
		LogLevel:                    envOr("LOG_LEVEL", "info"),
		TelegramTimeout:             durationOr("TELEGRAM_TIMEOUT", 5*time.Second),
		TelegramPollingEnabled:      pollingEnabled,
		TelegramPollingTimeout:      durationOr("TELEGRAM_POLLING_TIMEOUT", 25*time.Second),
		TelegramPollingInterval:     durationOr("TELEGRAM_POLLING_INTERVAL", time.Second),
		TelegramPollingLimit:        intOr("TELEGRAM_POLLING_LIMIT", 50),
		TelegramPollingDropPending:  boolOr("TELEGRAM_POLLING_DROP_PENDING", true),
		TelegramPollingDropWebhook:  boolOr("TELEGRAM_POLLING_DROP_WEBHOOK", true),
		TelegramInboundRateLimit:    inboundRate,
		TelegramWebhookURL:          envOr("TELEGRAM_WEBHOOK_URL", ""),
		TelegramWebhookDropPending:  boolOr("TELEGRAM_WEBHOOK_DROP_PENDING", false),
		APITimeout:                  durationOr("API_TIMEOUT", 5*time.Second),
		OTPSendPerMin:               otpPerMin,
		OTPSendIPPerMin:             intOr("OTP_RATE_LIMIT_IP_PER_MIN", otpPerMin),
		OTPSendBotPerMin:            otpBotPerMin,
		LinkTokenTTL:                durationOr("TELEGRAM_LINK_TTL", 10*time.Minute),
		LinkTokenRateLimitPerMin:    linkTokenPerMin,
		LinkTokenRateLimitIPPerMin:  intOr("LINK_TOKEN_RATE_LIMIT_IP_PER_MIN", linkTokenPerMin),
		LinkTokenRateLimitBotPerMin: intOr("LINK_TOKEN_RATE_LIMIT_BOT_PER_MIN", linkTokenPerMin),
		DBDriver:                    envOr("DB_DRIVER", "postgres"),
		RedisURL:                    envOr("REDIS_URL", ""),
	}

	cfg.BotToken = strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	cfg.WebhookSecret = strings.TrimSpace(os.Getenv("TELEGRAM_WEBHOOK_SECRET"))
	cfg.InternalAuthKey = strings.TrimSpace(os.Getenv("OTP_BOT_INTERNAL_KEY"))
	cfg.APIBaseURL = strings.TrimSpace(os.Getenv("API_BASE_URL"))
	cfg.APIInternalKey = strings.TrimSpace(os.Getenv("API_INTERNAL_KEY"))
	if cfg.InternalAuthKey == "" {
		cfg.InternalAuthKey = strings.TrimSpace(os.Getenv("INTERNAL_AUTH_KEY"))
	}
	if cfg.APIInternalKey == "" {
		cfg.APIInternalKey = cfg.InternalAuthKey
	}
	cfg.DatabaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	cfg.DBDriver = strings.ToLower(cfg.DBDriver)
	if cfg.DBDriver == "pq" || cfg.DBDriver == "postgresql" {
		cfg.DBDriver = "postgres"
	}

	missing := make([]string, 0, 4)
	if cfg.BotToken == "" {
		missing = append(missing, "TELEGRAM_BOT_TOKEN")
	}
	if cfg.InternalAuthKey == "" {
		missing = append(missing, "OTP_BOT_INTERNAL_KEY")
	}
	if cfg.APIBaseURL == "" {
		missing = append(missing, "API_BASE_URL")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}
	if cfg.LinkTokenTTL < 5*time.Minute || cfg.LinkTokenTTL > 10*time.Minute {
		return Config{}, fmt.Errorf("TELEGRAM_LINK_TTL must be between 5m and 10m")
	}
	invalidLimits := make([]string, 0, 6)
	if cfg.OTPSendPerMin <= 0 {
		invalidLimits = append(invalidLimits, "OTP_RATE_LIMIT_PER_MIN")
	}
	if cfg.OTPSendIPPerMin <= 0 {
		invalidLimits = append(invalidLimits, "OTP_RATE_LIMIT_IP_PER_MIN")
	}
	if cfg.OTPSendBotPerMin <= 0 {
		invalidLimits = append(invalidLimits, "OTP_RATE_LIMIT_BOT_PER_MIN")
	}
	if cfg.LinkTokenRateLimitPerMin <= 0 {
		invalidLimits = append(invalidLimits, "LINK_TOKEN_RATE_LIMIT_PER_MIN")
	}
	if cfg.LinkTokenRateLimitIPPerMin <= 0 {
		invalidLimits = append(invalidLimits, "LINK_TOKEN_RATE_LIMIT_IP_PER_MIN")
	}
	if cfg.LinkTokenRateLimitBotPerMin <= 0 {
		invalidLimits = append(invalidLimits, "LINK_TOKEN_RATE_LIMIT_BOT_PER_MIN")
	}
	if cfg.TelegramInboundRateLimit < 0 {
		invalidLimits = append(invalidLimits, "TELEGRAM_INBOUND_RATE_LIMIT_PER_MIN")
	}
	if len(invalidLimits) > 0 {
		return Config{}, fmt.Errorf("rate limit values must be positive: %s", strings.Join(invalidLimits, ", "))
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func durationOr(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return duration
}

func intOr(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func boolOr(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}
