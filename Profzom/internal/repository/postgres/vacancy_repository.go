package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"

	"profzom/internal/common"
	"profzom/internal/domain/vacancy"
)

type VacancyRepository struct {
	db *sql.DB
}

func NewVacancyRepository(db *sql.DB) *VacancyRepository {
	return &VacancyRepository{db: db}
}

func (r *VacancyRepository) Create(ctx context.Context, v vacancy.Vacancy) (*vacancy.Vacancy, error) {
	v.ID = common.NewUUID()
	now := time.Now().UTC()
	v.CreatedAt = now
	v.UpdatedAt = now
	_, err := r.db.ExecContext(ctx, `INSERT INTO vacancies (id, company_id, title, vacancy_type, description, requirements, conditions, salary, location, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		v.ID, v.CompanyID, v.Title, v.Type, v.Description, pq.Array(v.Requirements), pq.Array(v.Conditions), v.Salary, v.Location, v.Status, v.CreatedAt, v.UpdatedAt)
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to create vacancy", err)
	}
	return &v, nil
}

func (r *VacancyRepository) Update(ctx context.Context, v vacancy.Vacancy) (*vacancy.Vacancy, error) {
	v.UpdatedAt = time.Now().UTC()
	result, err := r.db.ExecContext(ctx, `UPDATE vacancies SET title = $1, vacancy_type = $2, description = $3, requirements = $4, conditions = $5, salary = $6, location = $7, status = $8, updated_at = $9
		WHERE id = $10 AND company_id = $11`,
		v.Title, v.Type, v.Description, pq.Array(v.Requirements), pq.Array(v.Conditions), v.Salary, v.Location, v.Status, v.UpdatedAt, v.ID, v.CompanyID)
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to update vacancy", err)
	}
	rows, err := result.RowsAffected()
	if err == nil && rows == 0 {
		return nil, common.NewError(common.CodeNotFound, "vacancy not found", sql.ErrNoRows)
	}
	return &v, nil
}

func (r *VacancyRepository) GetByID(ctx context.Context, id common.UUID) (*vacancy.Vacancy, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, company_id, title, vacancy_type, description, requirements, conditions, salary, location, status, created_at, updated_at FROM vacancies WHERE id = $1`, id)
	var v vacancy.Vacancy
	if err := row.Scan(&v.ID, &v.CompanyID, &v.Title, &v.Type, &v.Description, pq.Array(&v.Requirements), pq.Array(&v.Conditions), &v.Salary, &v.Location, &v.Status, &v.CreatedAt, &v.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, common.NewError(common.CodeNotFound, "vacancy not found", err)
		}
		return nil, common.NewError(common.CodeInternal, "failed to load vacancy", err)
	}
	return &v, nil
}

func (r *VacancyRepository) ListPublished(ctx context.Context, limit, offset int) ([]vacancy.Vacancy, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, company_id, title, vacancy_type, description, requirements, conditions, salary, location, status, created_at, updated_at
		FROM vacancies WHERE status = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, vacancy.StatusPublished, limit, offset)
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to list vacancies", err)
	}
	defer rows.Close()
	var items []vacancy.Vacancy
	for rows.Next() {
		var v vacancy.Vacancy
		if err := rows.Scan(&v.ID, &v.CompanyID, &v.Title, &v.Type, &v.Description, pq.Array(&v.Requirements), pq.Array(&v.Conditions), &v.Salary, &v.Location, &v.Status, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, common.NewError(common.CodeInternal, "failed to scan vacancy", err)
		}
		items = append(items, v)
	}
	return items, nil
}

func (r *VacancyRepository) ListPublishedFiltered(ctx context.Context, limit, offset int, skills []string) ([]vacancy.Vacancy, error) {
	if len(skills) == 0 {
		return r.ListPublished(ctx, limit, offset)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, company_id, title, vacancy_type, description, requirements, conditions, salary, location, status, created_at, updated_at
		FROM vacancies WHERE status = $1 AND requirements && $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`, vacancy.StatusPublished, pq.Array(skills), limit, offset)
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to list vacancies", err)
	}
	defer rows.Close()
	var items []vacancy.Vacancy
	for rows.Next() {
		var v vacancy.Vacancy
		if err := rows.Scan(&v.ID, &v.CompanyID, &v.Title, &v.Type, &v.Description, pq.Array(&v.Requirements), pq.Array(&v.Conditions), &v.Salary, &v.Location, &v.Status, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, common.NewError(common.CodeInternal, "failed to scan vacancy", err)
		}
		items = append(items, v)
	}
	return items, nil
}

func (r *VacancyRepository) ListByCompany(ctx context.Context, companyID common.UUID) ([]vacancy.Vacancy, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, company_id, title, vacancy_type, description, requirements, conditions, salary, location, status, created_at, updated_at
		FROM vacancies WHERE company_id = $1 ORDER BY created_at DESC`, companyID)
	if err != nil {
		return nil, common.NewError(common.CodeInternal, "failed to list company vacancies", err)
	}
	defer rows.Close()
	var items []vacancy.Vacancy
	for rows.Next() {
		var v vacancy.Vacancy
		if err := rows.Scan(&v.ID, &v.CompanyID, &v.Title, &v.Type, &v.Description, pq.Array(&v.Requirements), pq.Array(&v.Conditions), &v.Salary, &v.Location, &v.Status, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, common.NewError(common.CodeInternal, "failed to scan vacancy", err)
		}
		items = append(items, v)
	}
	return items, nil
}
