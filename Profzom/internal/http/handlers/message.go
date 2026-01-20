package handlers

import (
	"net/http"
	"strconv"
	"time"

	"profzom/internal/app"
	"profzom/internal/common"
	"profzom/internal/http/middleware"
	"profzom/internal/http/response"
)

type MessageHandler struct {
	messages *app.MessageService
	limiter  middleware.Limiter
}

func NewMessageHandler(messages *app.MessageService, limiter middleware.Limiter) *MessageHandler {
	return &MessageHandler{messages: messages, limiter: limiter}
}

type messageRequest struct {
	Body string `json:"body"`
}

func (h *MessageHandler) Send(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	applicationID, err := idFromPath(r, 2)
	if err != nil {
		response.Error(w, err)
		return
	}
	var req messageRequest
	if err := decodeJSON(r, &req); err != nil {
		response.Error(w, err)
		return
	}
	if h.limiter != nil {
		key := "msg:" + applicationID.String() + ":" + userID.String()
		if !h.limiter.Allow(key, 1, 2*time.Second) {
			response.Error(w, common.NewError(common.CodeValidation, "messages are sent too frequently", nil))
			return
		}
	}
	created, err := h.messages.Send(r.Context(), applicationID, userID, req.Body)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, created)
}

func (h *MessageHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	applicationID, err := idFromPath(r, 2)
	if err != nil {
		response.Error(w, err)
		return
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		response.Error(w, common.NewValidationError("limit is required", map[string]string{"limit": "limit must be > 0"}))
		return
	}
	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil || offset < 0 {
		response.Error(w, common.NewValidationError("offset is required", map[string]string{"offset": "offset must be >= 0"}))
		return
	}
	items, err := h.messages.List(r.Context(), applicationID, userID, limit, offset)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, items)
}
