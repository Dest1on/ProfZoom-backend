package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPPort          string
	PostgresDSN       string
	JWTSecret         string
	OTPBotBaseURL     string
	OTPBotInternalKey string
	OTPBotTelegramUsername string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	OTPTTL            time.Duration
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	DBConnMaxIdle     time.Duration
	DBConnMaxLife     time.Duration
	RequestTimeout    time.Duration
}

func Load() *Config {
	cfg := &Config{
		HTTPPort:          getEnv("HTTP_PORT", "8080"),
		PostgresDSN:       getEnv("DATABASE_URL", ""),
		JWTSecret:         getEnv("JWT_SECRET", ""),
		OTPBotBaseURL:     getEnv("OTP_BOT_BASE_URL", ""),
		OTPBotInternalKey: getEnv("OTP_BOT_INTERNAL_KEY", ""),
		OTPBotTelegramUsername: getEnv("OTP_BOT_TELEGRAM_USERNAME", ""),
		AccessTokenTTL:    getDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:   getDuration("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		OTPTTL:            getDuration("OTP_TTL", 5*time.Minute),
		DBMaxOpenConns:    getInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns:    getInt("DB_MAX_IDLE_CONNS", 10),
		DBConnMaxIdle:     getDuration("DB_CONN_MAX_IDLE", 5*time.Minute),
		DBConnMaxLife:     getDuration("DB_CONN_MAX_LIFE", 30*time.Minute),
		RequestTimeout:    getDuration("REQUEST_TIMEOUT", 10*time.Second),
	}

	if cfg.PostgresDSN == "" {
		log.Fatal("DATABASE_URL is required")
	}
	if cfg.JWTSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}
	if cfg.OTPBotBaseURL == "" {
		log.Fatal("OTP_BOT_BASE_URL is required")
	}
	if cfg.OTPBotInternalKey == "" {
		log.Fatal("OTP_BOT_INTERNAL_KEY is required")
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getDuration(key string, fallback time.Duration) time.Duration {
	if value, ok := os.LookupEnv(key); ok {
		parsed, err := time.ParseDuration(value)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func getInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		parsed, err := strconv.Atoi(value)
		if err == nil {
			return parsed
		}
	}
	return fallback
}
