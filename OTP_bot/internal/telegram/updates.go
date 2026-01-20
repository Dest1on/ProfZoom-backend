package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type getUpdatesResponse struct {
	OK          bool     `json:"ok"`
	Result      []Update `json:"result"`
	Description string   `json:"description,omitempty"`
}

type webhookResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
}

func (c *Client) GetUpdates(ctx context.Context, offset int64, timeout time.Duration, limit int) ([]Update, error) {
	payload := map[string]any{
		"allowed_updates": []string{"message"},
	}
	if offset > 0 {
		payload["offset"] = offset
	}
	if timeout > 0 {
		seconds := int(timeout.Round(time.Second).Seconds())
		if seconds < 0 {
			seconds = 0
		}
		if seconds > 50 {
			seconds = 50
		}
		payload["timeout"] = seconds
	}
	if limit > 0 {
		if limit > 100 {
			limit = 100
		}
		payload["limit"] = limit
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("telegram get updates encode: %w", err)
	}

	endpoint := fmt.Sprintf("%s/bot%s/getUpdates", c.baseURL, c.botToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("telegram get updates request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("telegram get updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(payload)}
	}

	var parsed getUpdatesResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("telegram get updates decode: %w", err)
	}
	if !parsed.OK {
		return nil, fmt.Errorf("telegram get updates error: %s", parsed.Description)
	}
	return parsed.Result, nil
}

func (c *Client) DeleteWebhook(ctx context.Context, dropPending bool) error {
	payload := map[string]any{}
	if dropPending {
		payload["drop_pending_updates"] = true
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram delete webhook encode: %w", err)
	}

	endpoint := fmt.Sprintf("%s/bot%s/deleteWebhook", c.baseURL, c.botToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram delete webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram delete webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return &APIError{StatusCode: resp.StatusCode, Body: string(payload)}
	}

	var parsed webhookResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return fmt.Errorf("telegram delete webhook decode: %w", err)
	}
	if !parsed.OK {
		return fmt.Errorf("telegram delete webhook error: %s", parsed.Description)
	}
	return nil
}

func (c *Client) SetWebhook(ctx context.Context, url, secretToken string, dropPending bool) error {
	if strings.TrimSpace(url) == "" {
		return fmt.Errorf("telegram set webhook: url is required")
	}
	payload := map[string]any{
		"url":             url,
		"allowed_updates": []string{"message"},
	}
	if secretToken != "" {
		payload["secret_token"] = secretToken
	}
	if dropPending {
		payload["drop_pending_updates"] = true
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram set webhook encode: %w", err)
	}

	endpoint := fmt.Sprintf("%s/bot%s/setWebhook", c.baseURL, c.botToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram set webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram set webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return &APIError{StatusCode: resp.StatusCode, Body: string(payload)}
	}

	var parsed webhookResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return fmt.Errorf("telegram set webhook decode: %w", err)
	}
	if !parsed.OK {
		return fmt.Errorf("telegram set webhook error: %s", parsed.Description)
	}
	return nil
}
