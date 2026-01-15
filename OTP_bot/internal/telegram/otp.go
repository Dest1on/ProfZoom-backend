package telegram

import (
	"context"
	"errors"
	"time"
)

var (
	ErrOTPNotLinked    = errors.New("telegram not linked")
	ErrOTPRateLimited  = errors.New("otp rate limited")
	ErrOTPInvalid      = errors.New("otp invalid")
	ErrOTPBadRequest   = errors.New("otp bad request")
	ErrOTPUnauthorized = errors.New("otp unauthorized")
)

type OTPRequest struct {
	Code      string
	ExpiresAt time.Time
}

type OTPVerifyResult struct {
	Token     string
	IsNewUser bool
}

type OTPClient interface {
	RequestOTP(ctx context.Context, chatID int64) (OTPRequest, error)
	VerifyOTP(ctx context.Context, chatID int64, code string) (OTPVerifyResult, error)
}
