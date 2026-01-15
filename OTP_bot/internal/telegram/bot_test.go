package telegram

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type fakeSender struct {
	lastChatID int64
	lastText   string
}

func (f *fakeSender) SendMessage(ctx context.Context, chatID int64, text string) error {
	f.lastChatID = chatID
	f.lastText = text
	return nil
}

type fakeVerifier struct {
	phone string
	err   error
}

func (f fakeVerifier) VerifyAndLink(ctx context.Context, token string, chatID int64) (string, error) {
	return f.phone, f.err
}

type fakeOTPClient struct {
	requestResp       OTPRequest
	requestErr        error
	verifyErr         error
	lastRequestChatID int64
	lastVerifyChatID  int64
	lastVerifyCode    string
}

func (f *fakeOTPClient) RequestOTP(ctx context.Context, chatID int64) (OTPRequest, error) {
	f.lastRequestChatID = chatID
	return f.requestResp, f.requestErr
}

func (f *fakeOTPClient) VerifyOTP(ctx context.Context, chatID int64, code string) (OTPVerifyResult, error) {
	f.lastVerifyChatID = chatID
	f.lastVerifyCode = code
	return OTPVerifyResult{}, f.verifyErr
}

func TestBotHandleStartSuccess(t *testing.T) {
	sender := &fakeSender{}
	verifier := fakeVerifier{phone: "+15550001111"}
	bot := NewBot(sender, verifier, nil, nil, slog.Default())

	update := Update{Message: &Message{Chat: Chat{ID: 42, Type: "private"}, Text: "/start token"}}
	if err := bot.HandleUpdate(context.Background(), update); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sender.lastChatID != 42 {
		t.Fatalf("expected chat id 42, got %d", sender.lastChatID)
	}
	if sender.lastText == "" {
		t.Fatalf("expected response text")
	}
}

func TestBotHandleStartInvalidToken(t *testing.T) {
	sender := &fakeSender{}
	verifier := fakeVerifier{err: ErrInvalidToken}
	bot := NewBot(sender, verifier, nil, nil, slog.Default())

	update := Update{Message: &Message{Chat: Chat{ID: 99, Type: "private"}, Text: "/start token"}}
	if err := bot.HandleUpdate(context.Background(), update); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sender.lastText == "" {
		t.Fatalf("expected response text")
	}
}

func TestBotHandleStartBackendError(t *testing.T) {
	sender := &fakeSender{}
	verifier := fakeVerifier{err: errors.New("backend down")}
	bot := NewBot(sender, verifier, nil, nil, slog.Default())

	update := Update{Message: &Message{Chat: Chat{ID: 7, Type: "private"}, Text: "/start token"}}
	if err := bot.HandleUpdate(context.Background(), update); err == nil {
		t.Fatalf("expected error")
	}
}

func TestBotHandleCodeRequest(t *testing.T) {
	sender := &fakeSender{}
	otpClient := &fakeOTPClient{
		requestResp: OTPRequest{Code: "123456", ExpiresAt: time.Now().Add(5 * time.Minute)},
	}
	bot := NewBot(sender, fakeVerifier{}, nil, otpClient, slog.Default())

	update := Update{Message: &Message{Chat: Chat{ID: 11, Type: "private"}, Text: "/code"}}
	if err := bot.HandleUpdate(context.Background(), update); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if otpClient.lastRequestChatID != 11 {
		t.Fatalf("expected chat id 11, got %d", otpClient.lastRequestChatID)
	}
	if !strings.Contains(sender.lastText, "123456") {
		t.Fatalf("expected response to contain code, got %q", sender.lastText)
	}
}

func TestBotHandleCodeVerify(t *testing.T) {
	sender := &fakeSender{}
	otpClient := &fakeOTPClient{}
	bot := NewBot(sender, fakeVerifier{}, nil, otpClient, slog.Default())

	update := Update{Message: &Message{Chat: Chat{ID: 22, Type: "private"}, Text: "/code 654321"}}
	if err := bot.HandleUpdate(context.Background(), update); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if otpClient.lastVerifyChatID != 22 {
		t.Fatalf("expected chat id 22, got %d", otpClient.lastVerifyChatID)
	}
	if otpClient.lastVerifyCode != "654321" {
		t.Fatalf("expected code 654321, got %q", otpClient.lastVerifyCode)
	}
}
