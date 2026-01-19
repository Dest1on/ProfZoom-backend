package app

import (
	"context"
	"fmt"
	"strings"

	"profzom/internal/common"
	"profzom/internal/domain/analytics"
	"profzom/internal/domain/profile"
	"profzom/internal/domain/vacancy"
)

type VacancyService struct {
	repo      vacancy.Repository
	companies profile.CompanyRepository
	students  profile.StudentRepository
	analytics analytics.Repository
}

func NewVacancyService(repo vacancy.Repository, companies profile.CompanyRepository, students profile.StudentRepository, analytics analytics.Repository) *VacancyService {
	return &VacancyService{repo: repo, companies: companies, students: students, analytics: analytics}
}

func (s *VacancyService) Create(ctx context.Context, v vacancy.Vacancy) (*vacancy.Vacancy, error) {
	if v.Title == "" {
		return nil, common.NewError(common.CodeValidation, "title is required", nil)
	}
	if v.Type == "" {
		return nil, common.NewError(common.CodeValidation, "type is required", nil)
	}
	if v.Description == "" {
		return nil, common.NewError(common.CodeValidation, "description is required", nil)
	}
	if len(v.Requirements) == 0 {
		return nil, common.NewError(common.CodeValidation, "requirements are required", nil)
	}
	if len(v.Conditions) == 0 {
		return nil, common.NewError(common.CodeValidation, "conditions are required", nil)
	}
	if v.Salary == "" {
		return nil, common.NewError(common.CodeValidation, "salary is required", nil)
	}
	if v.Location == "" {
		return nil, common.NewError(common.CodeValidation, "location is required", nil)
	}
	if v.Status == "" {
		v.Status = vacancy.StatusPublished
	}
	if err := validateVacancyStatus(v.Status); err != nil {
		return nil, err
	}
	created, err := s.repo.Create(ctx, v)
	if err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "vacancy.created", UserID: &v.CompanyID, Payload: analyticsPayload(ctx, map[string]string{"vacancy_id": created.ID.String()})})
	return created, nil
}

func (s *VacancyService) Update(ctx context.Context, v vacancy.Vacancy) (*vacancy.Vacancy, error) {
	current, err := s.repo.GetByID(ctx, v.ID)
	if err != nil {
		return nil, err
	}
	if current.CompanyID != v.CompanyID {
		return nil, common.NewError(common.CodeForbidden, "vacancy belongs to another company", nil)
	}
	if v.Status == "" {
		v.Status = current.Status
	}
	if err := validateVacancyStatus(v.Status); err != nil {
		return nil, err
	}
	if v.Status == vacancy.StatusPublished && current.Status != vacancy.StatusPublished {
		if err := s.ensurePublishable(ctx, v.CompanyID, v); err != nil {
			return nil, err
		}
	}
	updated, err := s.repo.Update(ctx, v)
	if err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "vacancy.updated", UserID: &v.CompanyID, Payload: analyticsPayload(ctx, map[string]string{"vacancy_id": updated.ID.String()})})
	return updated, nil
}

func (s *VacancyService) Publish(ctx context.Context, companyID, vacancyID common.UUID) (*vacancy.Vacancy, error) {
	v, err := s.repo.GetByID(ctx, vacancyID)
	if err != nil {
		return nil, err
	}
	if v.CompanyID != companyID {
		return nil, common.NewError(common.CodeForbidden, "vacancy belongs to another company", nil)
	}
	if err := s.ensurePublishable(ctx, companyID, *v); err != nil {
		return nil, err
	}
	v.Status = vacancy.StatusPublished
	updated, err := s.repo.Update(ctx, *v)
	if err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "vacancy.published", UserID: &companyID, Payload: analyticsPayload(ctx, map[string]string{"vacancy_id": updated.ID.String()})})
	return updated, nil
}

func (s *VacancyService) UpdateStatus(ctx context.Context, companyID, vacancyID common.UUID, status vacancy.Status) (*vacancy.Vacancy, error) {
	v, err := s.repo.GetByID(ctx, vacancyID)
	if err != nil {
		return nil, err
	}
	if v.CompanyID != companyID {
		return nil, common.NewError(common.CodeForbidden, "vacancy belongs to another company", nil)
	}
	normalized, err := normalizeVacancyStatus(status)
	if err != nil {
		return nil, err
	}
	if normalized == vacancy.StatusPublished {
		if err := s.ensurePublishable(ctx, companyID, *v); err != nil {
			return nil, err
		}
	}
	v.Status = normalized
	updated, err := s.repo.Update(ctx, *v)
	if err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "vacancy.status_changed", UserID: &companyID, Payload: analyticsPayload(ctx, map[string]string{"vacancy_id": updated.ID.String(), "status": string(normalized)})})
	return updated, nil
}

func validateVacancyForPublish(v vacancy.Vacancy) error {
	fields := map[string]string{}
	if v.Title == "" {
		fields["title"] = "title is required"
	}
	if len(v.Title) < 4 || len(v.Title) > 120 {
		fields["title"] = "title must be between 4 and 120 characters"
	}
	if v.Type == "" {
		fields["type"] = "type is required"
	}
	if v.Description == "" {
		fields["description"] = "description is required"
	}
	if len(v.Requirements) == 0 {
		fields["requirements"] = "at least one requirement is required"
	}
	for i, req := range v.Requirements {
		if len(req) < 2 {
			fields[fmt.Sprintf("requirements[%d]", i)] = "requirement must be at least 2 characters"
		}
	}
	if len(v.Conditions) == 0 {
		fields["conditions"] = "at least one condition is required"
	}
	for i, cond := range v.Conditions {
		if len(cond) < 2 {
			fields[fmt.Sprintf("conditions[%d]", i)] = "condition must be at least 2 characters"
		}
	}
	if v.Salary == "" {
		fields["salary"] = "salary is required"
	}
	if v.Location == "" {
		fields["location"] = "location is required"
	}
	if len(fields) > 0 {
		return common.NewValidationError("invalid vacancy", fields)
	}
	return nil
}

func validateVacancyStatus(status vacancy.Status) error {
	_, err := normalizeVacancyStatus(status)
	return err
}

func normalizeVacancyStatus(status vacancy.Status) (vacancy.Status, error) {
	normalized := vacancy.Status(strings.ToLower(strings.TrimSpace(string(status))))
	switch normalized {
	case vacancy.StatusDraft, vacancy.StatusPublished, vacancy.StatusHidden, vacancy.StatusClosed:
		return normalized, nil
	default:
		return "", common.NewValidationError("invalid vacancy status", map[string]string{"status": "status must be draft, published, hidden, or closed"})
	}
}

func (s *VacancyService) ensurePublishable(ctx context.Context, companyID common.UUID, v vacancy.Vacancy) error {
	companyProfile, err := s.companies.GetByUserID(ctx, companyID)
	if err != nil {
		if common.Is(err, common.CodeNotFound) {
			return common.NewError(common.CodeValidation, "company profile is required", nil)
		}
		return err
	}
	if !IsCompanyProfileComplete(*companyProfile) {
		return common.NewError(common.CodeValidation, "company profile is incomplete", nil)
	}
	if err := validateVacancyForPublish(v); err != nil {
		return err
	}
	return nil
}

func (s *VacancyService) Get(ctx context.Context, id common.UUID) (*vacancy.Vacancy, error) {
	item, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if item.Status != vacancy.StatusPublished {
		return nil, common.NewError(common.CodeNotFound, "vacancy not found", nil)
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "vacancy.viewed", Payload: analyticsPayload(ctx, map[string]string{"vacancy_id": item.ID.String()})})
	return item, nil
}

func (s *VacancyService) GetByCompany(ctx context.Context, companyID, vacancyID common.UUID) (*vacancy.Vacancy, error) {
	item, err := s.repo.GetByID(ctx, vacancyID)
	if err != nil {
		return nil, err
	}
	if item.CompanyID != companyID {
		return nil, common.NewError(common.CodeForbidden, "vacancy belongs to another company", nil)
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "vacancy.viewed_company", UserID: &companyID, Payload: analyticsPayload(ctx, map[string]string{"vacancy_id": item.ID.String()})})
	return item, nil
}

func (s *VacancyService) ListPublished(ctx context.Context, limit, offset int) ([]vacancy.Vacancy, error) {
	items, err := s.repo.ListPublished(ctx, limit, offset)
	if err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "vacancy.listed", Payload: analyticsPayload(ctx, map[string]string{"count": fmt.Sprintf("%d", len(items))})})
	return items, nil
}

func (s *VacancyService) ListRecommended(ctx context.Context, studentID common.UUID, limit, offset int) ([]vacancy.Vacancy, error) {
	if s.students == nil {
		return nil, common.NewError(common.CodeInternal, "student profile repository not configured", nil)
	}
	studentProfile, err := s.students.GetByUserID(ctx, studentID)
	if err != nil {
		if common.Is(err, common.CodeNotFound) {
			return nil, common.NewError(common.CodeValidation, "student profile is required", nil)
		}
		return nil, err
	}
	items, err := s.repo.ListPublishedFiltered(ctx, limit, offset, studentProfile.Skills)
	if err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "vacancy.recommended_listed", UserID: &studentID, Payload: analyticsPayload(ctx, map[string]string{"count": fmt.Sprintf("%d", len(items))})})
	return items, nil
}

func (s *VacancyService) ListByCompany(ctx context.Context, companyID common.UUID) ([]vacancy.Vacancy, error) {
	return s.repo.ListByCompany(ctx, companyID)
}
