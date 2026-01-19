package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"profzom/internal/app"
	"profzom/internal/common"
	"profzom/internal/domain/vacancy"
	"profzom/internal/http/middleware"
	"profzom/internal/http/response"
)

type VacancyHandler struct {
	vacancies *app.VacancyService
}

func NewVacancyHandler(vacancies *app.VacancyService) *VacancyHandler {
	return &VacancyHandler{vacancies: vacancies}
}

type vacancyRequest struct {
	Title        string   `json:"title"`
	Type         string   `json:"type"`
	Description  string   `json:"description"`
	Requirements []string `json:"requirements"`
	Conditions   []string `json:"conditions"`
	Salary       string   `json:"salary"`
	Location     string   `json:"location"`
	Status       string   `json:"status"`
}

type vacancyStatusRequest struct {
	Status string `json:"status"`
}

func (h *VacancyHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	var req vacancyRequest
	if err := decodeJSON(r, &req); err != nil {
		response.Error(w, err)
		return
	}
	if req.Title == "" {
		response.Error(w, common.NewError(common.CodeValidation, "title is required", nil))
		return
	}
	created, err := h.vacancies.Create(r.Context(), vacancy.Vacancy{
		CompanyID:    userID,
		Title:        req.Title,
		Type:         req.Type,
		Description:  req.Description,
		Requirements: req.Requirements,
		Conditions:   req.Conditions,
		Salary:       req.Salary,
		Location:     req.Location,
		Status:       vacancy.Status(req.Status),
	})
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, created)
}

func (h *VacancyHandler) Update(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	vacancyID, err := idFromPath(r, 1)
	if err != nil {
		response.Error(w, err)
		return
	}
	var req vacancyRequest
	if err := decodeJSON(r, &req); err != nil {
		response.Error(w, err)
		return
	}
	if req.Title == "" {
		response.Error(w, common.NewError(common.CodeValidation, "title is required", nil))
		return
	}
	updated, err := h.vacancies.Update(r.Context(), vacancy.Vacancy{
		ID:           vacancyID,
		CompanyID:    userID,
		Title:        req.Title,
		Type:         req.Type,
		Description:  req.Description,
		Requirements: req.Requirements,
		Conditions:   req.Conditions,
		Salary:       req.Salary,
		Location:     req.Location,
		Status:       vacancy.Status(req.Status),
	})
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, updated)
}

func (h *VacancyHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	vacancyID, err := idFromPath(r, 2)
	if err != nil {
		response.Error(w, err)
		return
	}
	var req vacancyStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		response.Error(w, err)
		return
	}
	if strings.TrimSpace(req.Status) == "" {
		response.Error(w, common.NewError(common.CodeValidation, "status is required", nil))
		return
	}
	updated, err := h.vacancies.UpdateStatus(r.Context(), userID, vacancyID, vacancy.Status(req.Status))
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, updated)
}

func (h *VacancyHandler) Publish(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	vacancyID, err := idFromPath(r, 2)
	if err != nil {
		response.Error(w, err)
		return
	}
	updated, err := h.vacancies.Publish(r.Context(), userID, vacancyID)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, updated)
}

func (h *VacancyHandler) ListPublished(w http.ResponseWriter, r *http.Request) {
	limit := 20
	offset := 0
	if value := r.URL.Query().Get("limit"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			limit = parsed
		}
	}
	if value := r.URL.Query().Get("offset"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			offset = parsed
		}
	}
	items, err := h.vacancies.ListPublished(r.Context(), limit, offset)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, items)
}

func (h *VacancyHandler) ListRecommended(w http.ResponseWriter, r *http.Request) {
	studentID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	limit := 20
	offset := 0
	if value := r.URL.Query().Get("limit"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			limit = parsed
		}
	}
	if value := r.URL.Query().Get("offset"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			offset = parsed
		}
	}
	items, err := h.vacancies.ListRecommended(r.Context(), studentID, limit, offset)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, items)
}

func (h *VacancyHandler) ListByCompany(w http.ResponseWriter, r *http.Request) {
	companyID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	items, err := h.vacancies.ListByCompany(r.Context(), companyID)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, items)
}

func (h *VacancyHandler) GetByCompany(w http.ResponseWriter, r *http.Request) {
	companyID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		response.Error(w, errUnauthorized())
		return
	}
	vacancyID, err := idFromPath(r, 1)
	if err != nil {
		response.Error(w, err)
		return
	}
	item, err := h.vacancies.GetByCompany(r.Context(), companyID, vacancyID)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, item)
}

func (h *VacancyHandler) Get(w http.ResponseWriter, r *http.Request) {
	vacancyID, err := idFromPath(r, 1)
	if err != nil {
		response.Error(w, err)
		return
	}
	item, err := h.vacancies.Get(r.Context(), vacancyID)
	if err != nil {
		response.Error(w, err)
		return
	}
	response.JSON(w, http.StatusOK, item)
}
