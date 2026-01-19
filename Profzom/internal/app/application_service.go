package app

import (
	"context"
	"strings"

	"profzom/internal/common"
	"profzom/internal/domain/analytics"
	"profzom/internal/domain/application"
	"profzom/internal/domain/profile"
	"profzom/internal/domain/vacancy"
)

type ApplicationService struct {
	repo      application.Repository
	vacancies vacancy.Repository
	students  profile.StudentRepository
	analytics analytics.Repository
}

func NewApplicationService(repo application.Repository, vacancies vacancy.Repository, students profile.StudentRepository, analytics analytics.Repository) *ApplicationService {
	return &ApplicationService{repo: repo, vacancies: vacancies, students: students, analytics: analytics}
}

func (s *ApplicationService) Apply(ctx context.Context, vacancyID, studentID common.UUID) (*application.Application, error) {
	studentProfile, err := s.students.GetByUserID(ctx, studentID)
	if err != nil {
		if common.Is(err, common.CodeNotFound) {
			return nil, common.NewError(common.CodeValidation, "student profile is required", nil)
		}
		return nil, err
	}
	if !IsStudentProfileComplete(*studentProfile) {
		return nil, common.NewError(common.CodeValidation, "student profile is incomplete", nil)
	}
	vac, err := s.vacancies.GetByID(ctx, vacancyID)
	if err != nil {
		return nil, err
	}
	if vac.Status != vacancy.StatusPublished {
		return nil, common.NewError(common.CodeValidation, "vacancy is not published", nil)
	}
	if _, err := s.repo.FindByVacancyAndStudent(ctx, vacancyID, studentID); err == nil {
		return nil, common.NewError(common.CodeConflict, "already applied", nil)
	} else if !common.Is(err, common.CodeNotFound) {
		return nil, err
	}
	app := application.Application{
		VacancyID: vacancyID,
		StudentID: studentID,
		Status:    application.StatusApplied,
	}
	created, err := s.repo.Create(ctx, app)
	if err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "application.created", UserID: &studentID, Payload: analyticsPayload(ctx, map[string]string{"application_id": created.ID.String(), "vacancy_id": vacancyID.String()})})
	return created, nil
}

func (s *ApplicationService) UpdateStatus(ctx context.Context, applicationID common.UUID, status application.Status, feedback string, companyID common.UUID) (*application.Application, error) {
	app, err := s.repo.GetByID(ctx, applicationID)
	if err != nil {
		return nil, err
	}
	vac, err := s.vacancies.GetByID(ctx, app.VacancyID)
	if err != nil {
		return nil, err
	}
	if vac.CompanyID != companyID {
		return nil, common.NewError(common.CodeForbidden, "application belongs to another company", nil)
	}
	currentStatus := normalizeApplicationStatus(app.Status)
	nextStatus := normalizeApplicationStatus(application.Status(strings.ToLower(strings.TrimSpace(string(status)))))
	if !isKnownStatus(nextStatus) {
		return nil, common.NewValidationError("invalid status", map[string]string{"status": "status must be applied, in_review, invited, accepted, or rejected"})
	}
	if nextStatus == currentStatus {
		updated, err := s.repo.UpdateStatus(ctx, applicationID, nextStatus, feedback)
		if err != nil {
			return nil, err
		}
		if feedback != "" {
			_ = s.analytics.Create(ctx, analytics.Event{Name: "application.feedback_updated", UserID: &companyID, Payload: analyticsPayload(ctx, map[string]string{"application_id": updated.ID.String(), "status": string(nextStatus)})})
		}
		return updated, nil
	}
	if isFinalStatus(currentStatus) {
		return nil, common.NewError(common.CodeValidation, "application status is final", nil)
	}
	if !isAllowedTransition(currentStatus, nextStatus) {
		return nil, common.NewError(common.CodeValidation, "invalid status transition", nil)
	}
	updated, err := s.repo.UpdateStatus(ctx, applicationID, nextStatus, feedback)
	if err != nil {
		return nil, err
	}
	_ = s.analytics.Create(ctx, analytics.Event{Name: "application.status_changed", UserID: &companyID, Payload: analyticsPayload(ctx, map[string]string{"application_id": updated.ID.String(), "status": string(status)})})
	return updated, nil
}

func isAllowedTransition(from application.Status, to application.Status) bool {
	switch from {
	case application.StatusApplied:
		return to == application.StatusInReview || to == application.StatusInvited || to == application.StatusRejected || to == application.StatusAccepted
	case application.StatusInReview:
		return to == application.StatusInvited || to == application.StatusRejected || to == application.StatusAccepted
	case application.StatusInvited:
		return to == application.StatusAccepted || to == application.StatusRejected
	default:
		return false
	}
}

func isFinalStatus(status application.Status) bool {
	return status == application.StatusRejected || status == application.StatusAccepted
}

func normalizeApplicationStatus(status application.Status) application.Status {
	normalized := application.Status(strings.ToLower(strings.TrimSpace(string(status))))
	if normalized == "interview" {
		return application.StatusInvited
	}
	if normalized == "review" || normalized == "in_review" {
		return application.StatusInReview
	}
	return normalized
}

func isKnownStatus(status application.Status) bool {
	switch status {
	case application.StatusApplied, application.StatusInReview, application.StatusInvited, application.StatusAccepted, application.StatusRejected:
		return true
	default:
		return false
	}
}

func (s *ApplicationService) ListByStudent(ctx context.Context, studentID common.UUID) ([]application.Application, error) {
	return s.repo.ListByStudent(ctx, studentID)
}

func (s *ApplicationService) ListByCompany(ctx context.Context, companyID common.UUID) ([]application.Application, error) {
	return s.repo.ListByCompany(ctx, companyID)
}

func (s *ApplicationService) Get(ctx context.Context, id common.UUID) (*application.Application, error) {
	return s.repo.GetByID(ctx, id)
}
