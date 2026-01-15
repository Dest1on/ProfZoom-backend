package handlers

import (
	"net/http"
	"strings"

	"profzom/internal/http/response"
)

const (
	internalAuthHeader    = "Authorization"
	internalAuthAltHeader = "X-Internal-Key"
)

func requireInternalAuth(w http.ResponseWriter, r *http.Request, internalKey string) bool {
	key := strings.TrimSpace(internalKey)
	if key == "" {
		response.Error(w, errUnauthorized())
		return false
	}
	altValue := strings.TrimSpace(r.Header.Get(internalAuthAltHeader))
	value := strings.TrimSpace(r.Header.Get(internalAuthHeader))
	if altValue == key || value == "Bearer "+key {
		return true
	}
	response.Error(w, errUnauthorized())
	return false
}
