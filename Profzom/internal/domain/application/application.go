package application

import (
	"time"

	"profzom/internal/common"
)

type Status string

const (
	StatusApplied  Status = "applied"
	StatusInReview Status = "in_review"
	StatusInvited  Status = "invited"
	StatusRejected Status = "rejected"
	StatusAccepted Status = "accepted"
)

type Application struct {
	ID        common.UUID `json:"id"`
	VacancyID common.UUID `json:"vacancy_id"`
	StudentID common.UUID `json:"student_id"`
	Status    Status      `json:"status"`
	Feedback  string      `json:"feedback,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}
