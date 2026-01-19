package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"profzom/internal/common"
)

type JWTProvider struct {
	secret []byte
}

func NewJWTProvider(secret string) *JWTProvider {
	return &JWTProvider{secret: []byte(secret)}
}

type Claims struct {
	Sub    string   `json:"sub,omitempty"`
	UserID string   `json:"user_id,omitempty"`
	Roles  []string `json:"roles"`
	Role   string   `json:"role,omitempty"`
	Exp    int64    `json:"exp"`
	Iat    int64    `json:"iat"`
}

func (p *JWTProvider) Generate(userID common.UUID, roles []string, activeRole string, ttl time.Duration) (string, time.Time, error) {
	expiresAt := time.Now().UTC().Add(ttl)
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	claims := Claims{
		Sub:    string(userID),
		UserID: string(userID),
		Roles:  roles,
		Role:   strings.TrimSpace(activeRole),
		Exp:    expiresAt.Unix(),
		Iat:    time.Now().UTC().Unix(),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", time.Time{}, err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerEnc + "." + payloadEnc
	sig := signHS256(signingInput, p.secret)
	return signingInput + "." + sig, expiresAt, nil
}

func (p *JWTProvider) Parse(tokenString string) (*Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}
	signingInput := parts[0] + "." + parts[1]
	signature := parts[2]
	if !verifyHS256(signingInput, signature, p.secret) {
		return nil, errors.New("invalid token signature")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, err
	}
	if claims.UserID == "" && claims.Sub != "" {
		claims.UserID = claims.Sub
	}
	if claims.Exp > 0 && time.Now().UTC().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}

func signHS256(input string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func verifyHS256(input, signature string, secret []byte) bool {
	expected := signHS256(input, secret)
	return hmac.Equal([]byte(signature), []byte(expected))
}
