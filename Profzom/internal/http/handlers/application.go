package handlers

import (
	"net/http"
	"strings"
	"time"

	"profzom/internal/app"
	"profzom/internal/common"
	"profzom/internal/domain/application"
	"profzom/internal/domain/user"
	"profzom/internal/http/middleware"
	"profzom/internal/http/response"
)

type ApplicationHandler struct {
	applications *app.ApplicationService
	limiter      middleware.Limiter
}

func NewApplicationHandler(applications *app.ApplicationService, limiter middleware.Limiter) *ApplicationHandler {
	return &ApplicationHandler{applications: applications, limiter: limiter}
}

type applyRequest struct {
	VacancyID string `json:"vacancy_id"`
}

func (h *ApplicationHandler) Apply(w http.ResponseWriter, r *http.Request) {
	studentID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	vacancyID, err := vacancyIDFromRequest(r)
	if err != nil {
		response.Error(w, err)
		return
	}
	if h.limiter != nil {
		key := "apply:" + vacancyID.String() + ":" + studentID.String()
		if !h.limiter.Allow(key, 3, time.Minute) {
			response.Error(w, common.NewError(common.CodeRateLimited, "apply rate limit exceeded", nil))
			return
		}
	}
	created, err := h.applications.Apply(r.Context(), vacancyID, studentID)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, created)
}

func (h *ApplicationHandler) ListStudent(w http.ResponseWriter, r *http.Request) {
	studentID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	items, err := h.applications.ListByStudent(r.Context(), studentID)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, items)
}

func (h *ApplicationHandler) ListCompany(w http.ResponseWriter, r *http.Request) {
	companyID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	if value := strings.TrimSpace(r.URL.Query().Get("company_id")); value != "" {
		requestedID, err := common.ParseUUID(value)
		if err != nil {
			response.Error(w, common.NewValidationError("invalid company_id", map[string]string{"company_id": "invalid uuid"}))
			return
		}
		if requestedID != companyID {
			response.Error(w, common.NewError(common.CodeForbidden, "company_id does not match token", nil))
			return
		}
	}
	items, err := h.applications.ListByCompany(r.Context(), companyID)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, items)
}

func (h *ApplicationHandler) List(w http.ResponseWriter, r *http.Request) {
	activeRole, ok := middleware.ActiveRoleFromContext(r.Context())
	if !ok || activeRole == "" {
		response.Error(w, common.NewError(common.CodeForbidden, "role not selected", nil))
		return
	}
	switch activeRole {
	case user.RoleStudent:
		h.ListStudent(w, r)
	case user.RoleCompany:
		h.ListCompany(w, r)
	default:
		response.Error(w, common.NewError(common.CodeForbidden, "insufficient role", nil))
	}
}

type updateStatusRequest struct {
	Status   string `json:"status"`
	Feedback string `json:"feedback"`
}

func (h *ApplicationHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	companyID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	applicationID, err := idFromPath(r, 2)
	if err != nil {
		response.Error(w, err)
		return
	}
	var req updateStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		response.Error(w, err)
		return
	}
	if req.Status == "" {
		response.Error(w, common.NewError(common.CodeValidation, "status is required", nil))
		return
	}
	updated, err := h.applications.UpdateStatus(r.Context(), applicationID, application.Status(req.Status), req.Feedback, companyID)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, updated)
}

func vacancyIDFromRequest(r *http.Request) (common.UUID, error) {
	var req applyRequest
	if err := decodeJSON(r, &req); err != nil {
		return "", err
	}
	if strings.TrimSpace(req.VacancyID) == "" {
		return "", common.NewValidationError("invalid request", map[string]string{"vacancy_id": "vacancy_id is required"})
	}
	parsed, err := common.ParseUUID(req.VacancyID)
	if err != nil {
		return "", common.NewValidationError("invalid request", map[string]string{"vacancy_id": "invalid uuid"})
	}
	return parsed, nil
}
