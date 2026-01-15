package profzom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"otp_bot/internal/telegram"
)

type HTTPClient struct {
	baseURL     string
	internalKey string
	httpClient  *http.Client
}

func NewClient(baseURL, internalKey string, httpClient *http.Client) *HTTPClient {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &HTTPClient{
		baseURL:     trimmed,
		internalKey: strings.TrimSpace(internalKey),
		httpClient:  httpClient,
	}
}

type requestOTPRequest struct {
	TelegramID int64 `json:"telegram_id"`
}

type requestOTPResponse struct {
	Code      string `json:"code"`
	ExpiresAt string `json:"expires_at"`
}

type verifyOTPRequest struct {
	TelegramID int64  `json:"telegram_id"`
	Code       string `json:"code"`
}

type verifyOTPResponse struct {
	Token     string `json:"token"`
	IsNewUser bool   `json:"is_new_user"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (c *HTTPClient) RequestOTP(ctx context.Context, chatID int64) (telegram.OTPRequest, error) {
	if chatID <= 0 {
		return telegram.OTPRequest{}, telegram.ErrOTPBadRequest
	}
	if c.baseURL == "" {
		return telegram.OTPRequest{}, telegram.ErrOTPUnauthorized
	}
	payload := requestOTPRequest{TelegramID: chatID}
	body, err := json.Marshal(payload)
	if err != nil {
		return telegram.OTPRequest{}, fmt.Errorf("encode otp request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/request-code", bytes.NewReader(body))
	if err != nil {
		return telegram.OTPRequest{}, fmt.Errorf("create otp request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.internalKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.internalKey)
		req.Header.Set("X-Internal-Key", c.internalKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return telegram.OTPRequest{}, fmt.Errorf("send otp request: %w", err)
	}
	defer resp.Body.Close()
	payloadBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return telegram.OTPRequest{}, fmt.Errorf("read otp response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return telegram.OTPRequest{}, mapOTPError(payloadBytes, false)
	}
	var parsed requestOTPResponse
	if err := json.Unmarshal(payloadBytes, &parsed); err != nil {
		return telegram.OTPRequest{}, fmt.Errorf("decode otp response: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, parsed.ExpiresAt)
	if err != nil {
		return telegram.OTPRequest{}, fmt.Errorf("parse expires_at: %w", err)
	}
	return telegram.OTPRequest{Code: parsed.Code, ExpiresAt: expiresAt}, nil
}

func (c *HTTPClient) VerifyOTP(ctx context.Context, chatID int64, code string) (telegram.OTPVerifyResult, error) {
	if chatID <= 0 || strings.TrimSpace(code) == "" {
		return telegram.OTPVerifyResult{}, telegram.ErrOTPBadRequest
	}
	if c.baseURL == "" {
		return telegram.OTPVerifyResult{}, telegram.ErrOTPUnauthorized
	}
	payload := verifyOTPRequest{TelegramID: chatID, Code: strings.TrimSpace(code)}
	body, err := json.Marshal(payload)
	if err != nil {
		return telegram.OTPVerifyResult{}, fmt.Errorf("encode verify request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/verify-code", bytes.NewReader(body))
	if err != nil {
		return telegram.OTPVerifyResult{}, fmt.Errorf("create verify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return telegram.OTPVerifyResult{}, fmt.Errorf("send verify request: %w", err)
	}
	defer resp.Body.Close()
	payloadBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return telegram.OTPVerifyResult{}, fmt.Errorf("read verify response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return telegram.OTPVerifyResult{}, mapOTPError(payloadBytes, true)
	}
	var parsed verifyOTPResponse
	if err := json.Unmarshal(payloadBytes, &parsed); err != nil {
		return telegram.OTPVerifyResult{}, fmt.Errorf("decode verify response: %w", err)
	}
	return telegram.OTPVerifyResult{Token: parsed.Token, IsNewUser: parsed.IsNewUser}, nil
}

func mapOTPError(payload []byte, isVerify bool) error {
	var parsed errorResponse
	if err := json.Unmarshal(payload, &parsed); err != nil {
		message := strings.TrimSpace(string(payload))
		if message == "" {
			return fmt.Errorf("otp api error")
		}
		return fmt.Errorf("otp api error: %s", message)
	}
	switch parsed.Error {
	case "telegram_not_linked":
		return telegram.ErrOTPNotLinked
	case "rate_limited":
		return telegram.ErrOTPRateLimited
	case "validation":
		return telegram.ErrOTPBadRequest
	case "unauthorized":
		if isVerify {
			return telegram.ErrOTPInvalid
		}
		return telegram.ErrOTPUnauthorized
	default:
		return fmt.Errorf("otp api error: %s", parsed.Error)
	}
}
