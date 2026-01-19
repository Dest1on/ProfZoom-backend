package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"profzom/internal/common"
	"profzom/internal/domain/application"
)

type ApplicationRepository struct {
	db *sql.DB
}

func NewApplicationRepository(db *sql.DB) *ApplicationRepository {
	return &ApplicationRepository{db: db}
}

func (r *ApplicationRepository) Create(ctx context.Context, app application.Application) (*application.Application, error) {
	app.ID = common.NewUUID()
	now := time.Now().UTC()
	app.CreatedAt = now
	app.UpdatedAt = now
	_, err := r.db.ExecContext(ctx, `INSERT INTO applications (id, vacancy_id, student_id, status, feedback, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		app.ID, app.VacancyID, app.StudentID, app.Status, app.Feedback, app.CreatedAt, app.UpdatedAt)
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to create application", err)
	}
	return &app, nil
}

func (r *ApplicationRepository) GetByID(ctx context.Context, id common.UUID) (*application.Application, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, vacancy_id, student_id, status, feedback, created_at, updated_at FROM applications WHERE id = $1`, id)
	var app application.Application
	if err := row.Scan(&app.ID, &app.VacancyID, &app.StudentID, &app.Status, &app.Feedback, &app.CreatedAt, &app.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, common.NewError(common.CodeNotFound, "application not found", err)
		}
		return nil, common.NewError(common.CodeInternal, "failed to load application", err)
	}
	app.Status = normalizeStatus(app.Status)
	return &app, nil
}

func (r *ApplicationRepository) ListByVacancy(ctx context.Context, vacancyID common.UUID) ([]application.Application, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, vacancy_id, student_id, status, feedback, created_at, updated_at FROM applications WHERE vacancy_id = $1`, vacancyID)
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to list applications", err)
	}
	defer rows.Close()
	var items []application.Application
	for rows.Next() {
		var app application.Application
		if err := rows.Scan(&app.ID, &app.VacancyID, &app.StudentID, &app.Status, &app.Feedback, &app.CreatedAt, &app.UpdatedAt); err != nil {
			return nil, common.NewError(common.CodeInternal, "failed to scan application", err)
		}
		app.Status = normalizeStatus(app.Status)
		items = append(items, app)
	}
	return items, nil
}

func (r *ApplicationRepository) ListByStudent(ctx context.Context, studentID common.UUID) ([]application.Application, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, vacancy_id, student_id, status, feedback, created_at, updated_at FROM applications WHERE student_id = $1`, studentID)
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to list student applications", err)
	}
	defer rows.Close()
	var items []application.Application
	for rows.Next() {
		var app application.Application
		if err := rows.Scan(&app.ID, &app.VacancyID, &app.StudentID, &app.Status, &app.Feedback, &app.CreatedAt, &app.UpdatedAt); err != nil {
			return nil, common.NewError(common.CodeInternal, "failed to scan application", err)
		}
		app.Status = normalizeStatus(app.Status)
		items = append(items, app)
	}
	return items, nil
}

func (r *ApplicationRepository) ListByCompany(ctx context.Context, companyID common.UUID) ([]application.Application, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT a.id, a.vacancy_id, a.student_id, a.status, a.feedback, a.created_at, a.updated_at
		FROM applications a
		JOIN vacancies v ON v.id = a.vacancy_id
		WHERE v.company_id = $1
		ORDER BY a.created_at DESC`, companyID)
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to list company applications", err)
	}
	defer rows.Close()
	var items []application.Application
	for rows.Next() {
		var app application.Application
		if err := rows.Scan(&app.ID, &app.VacancyID, &app.StudentID, &app.Status, &app.Feedback, &app.CreatedAt, &app.UpdatedAt); err != nil {
			return nil, common.NewError(common.CodeInternal, "failed to scan application", err)
		}
		app.Status = normalizeStatus(app.Status)
		items = append(items, app)
	}
	return items, nil
}

func (r *ApplicationRepository) UpdateStatus(ctx context.Context, id common.UUID, status application.Status, feedback string) (*application.Application, error) {
	updatedAt := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, `UPDATE applications SET status = $1, feedback = $2, updated_at = $3 WHERE id = $4`, status, feedback, updatedAt, id)
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to update application", err)
	}
	return r.GetByID(ctx, id)
}

func (r *ApplicationRepository) FindByVacancyAndStudent(ctx context.Context, vacancyID, studentID common.UUID) (*application.Application, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, vacancy_id, student_id, status, feedback, created_at, updated_at FROM applications WHERE vacancy_id = $1 AND student_id = $2`, vacancyID, studentID)
	var app application.Application
	if err := row.Scan(&app.ID, &app.VacancyID, &app.StudentID, &app.Status, &app.Feedback, &app.CreatedAt, &app.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, common.NewError(common.CodeNotFound, "application not found", err)
		}
		return nil, common.NewError(common.CodeInternal, "failed to load application", err)
	}
	app.Status = normalizeStatus(app.Status)
	return &app, nil
}

func normalizeStatus(status application.Status) application.Status {
	normalized := application.Status(strings.ToLower(strings.TrimSpace(string(status))))
	if normalized == "interview" {
		return application.StatusInvited
	}
	if normalized == "review" || normalized == "in_review" {
		return application.StatusInReview
	}
	return normalized
}
