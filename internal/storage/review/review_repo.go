// Package review stores access reviews (ADM-6).
package review

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/internal/storage"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/postgres"
)

type reviewRepository struct {
	log logger.Logger
}

func NewReviewRepository(log logger.Logger) storage.ReviewRepository {
	return &reviewRepository{log: log}
}

func (r *reviewRepository) CreateReview(ctx context.Context, tx pgx.Tx, tenantID, organizationID, reviewerID string, due *time.Time) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.access_reviews (tenant_id, organization_id, reviewer_principal_id, due_at) VALUES ($1, $2, $3, $4) RETURNING id::text`,
		tenantID, organizationID, postgres.NullString(reviewerID), due).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create review: %w", err)
	}
	return id, nil
}

func (r *reviewRepository) SnapshotGrants(ctx context.Context, tx pgx.Tx, tenantID, reviewID, organizationID string) (int64, error) {
	tag, err := tx.Exec(ctx, `
		INSERT INTO aos.access_review_items (tenant_id, review_id, grant_id)
		SELECT g.tenant_id, $2, g.id FROM aos.grants g
		JOIN aos.resource_ancestors a ON a.tenant_id = g.tenant_id AND a.resource_id = g.resource_id
		WHERE g.tenant_id = $1 AND a.ancestor_id = $3`, tenantID, reviewID, organizationID)
	if err != nil {
		return 0, fmt.Errorf("snapshot grants: %w", err)
	}
	return tag.RowsAffected(), nil
}

const reviewColumns = `id::text, COALESCE(organization_id::text, ''), status, COALESCE(reviewer_principal_id::text, ''), due_at, completed_at, created_at`

func scanReview(row pgx.CollectableRow) (model.AccessReview, error) {
	var a model.AccessReview
	err := row.Scan(&a.ID, &a.OrganizationID, &a.Status, &a.ReviewerID, &a.DueAt, &a.CompletedAt, &a.CreatedAt)
	return a, err
}

func (r *reviewRepository) GetReview(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.AccessReview, error) {
	if !postgres.IsUUID(id) {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+reviewColumns+` FROM aos.access_reviews WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("get review: %w", err)
	}
	a, err := pgx.CollectOneRow(rows, scanReview)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get review: %w", err)
	}
	return &a, nil
}

func (r *reviewRepository) ListReviews(ctx context.Context, tx pgx.Tx, tenantID, organizationID string) ([]model.AccessReview, error) {
	rows, err := tx.Query(ctx, `SELECT `+reviewColumns+` FROM aos.access_reviews WHERE tenant_id = $1 AND organization_id = $2 ORDER BY created_at DESC`, tenantID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list reviews: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanReview)
	if err != nil {
		return nil, fmt.Errorf("list reviews: %w", err)
	}
	return out, nil
}

const itemColumns = `i.id::text, i.grant_id::text, COALESCE(i.decision, ''), i.decided_at,
	COALESCE(g.principal_id::text, ''), COALESCE(g.group_id::text, ''), COALESCE(u.email::text, COALESCE(gr.name, '')), COALESCE(ro.name, ''),
	COALESCE(re.type, ''), COALESCE(re.external_id, ''), COALESCE(g.effect, ''), g.id IS NULL`

func scanItem(row pgx.CollectableRow) (model.AccessReviewItem, error) {
	var it model.AccessReviewItem
	err := row.Scan(&it.ID, &it.GrantID, &it.Decision, &it.DecidedAt, &it.PrincipalID, &it.GroupID, &it.Email, &it.Role, &it.ResourceType, &it.ResourceID, &it.Effect, &it.Gone)
	return it, err
}

const itemJoins = `FROM aos.access_review_items i
	LEFT JOIN aos.grants g ON g.tenant_id = i.tenant_id AND g.id = i.grant_id
	LEFT JOIN aos.roles ro ON ro.tenant_id = g.tenant_id AND ro.id = g.role_id
	LEFT JOIN aos.resources re ON re.tenant_id = g.tenant_id AND re.id = g.resource_id
	LEFT JOIN aos.users u ON u.tenant_id = g.tenant_id AND u.principal_id = g.principal_id
	LEFT JOIN aos.groups gr ON gr.tenant_id = g.tenant_id AND gr.id = g.group_id`

func (r *reviewRepository) ListItems(ctx context.Context, tx pgx.Tx, tenantID, reviewID string) ([]model.AccessReviewItem, error) {
	rows, err := tx.Query(ctx, `SELECT `+itemColumns+` `+itemJoins+` WHERE i.tenant_id = $1 AND i.review_id = $2 ORDER BY u.email, ro.name`, tenantID, reviewID)
	if err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanItem)
	if err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}
	return out, nil
}

func (r *reviewRepository) LockItem(ctx context.Context, tx pgx.Tx, tenantID, reviewID, itemID string) (*model.AccessReviewItem, error) {
	if !postgres.IsUUID(itemID) {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+itemColumns+` `+itemJoins+` WHERE i.tenant_id = $1 AND i.review_id = $2 AND i.id = $3 FOR UPDATE OF i`, tenantID, reviewID, itemID)
	if err != nil {
		return nil, fmt.Errorf("lock item: %w", err)
	}
	it, err := pgx.CollectOneRow(rows, scanItem)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock item: %w", err)
	}
	return &it, nil
}

func (r *reviewRepository) DecideItem(ctx context.Context, tx pgx.Tx, tenantID, itemID, decision string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE aos.access_review_items SET decision = $3, decided_at = $4 WHERE tenant_id = $1 AND id = $2`, tenantID, itemID, decision, at)
	return err
}

func (r *reviewRepository) CountUndecided(ctx context.Context, tx pgx.Tx, tenantID, reviewID string) (int64, error) {
	var n int64
	err := tx.QueryRow(ctx, `SELECT count(*) FROM aos.access_review_items WHERE tenant_id = $1 AND review_id = $2 AND decision IS NULL`, tenantID, reviewID).Scan(&n)
	return n, err
}

func (r *reviewRepository) CompleteReview(ctx context.Context, tx pgx.Tx, tenantID, reviewID string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE aos.access_reviews SET status = 'completed', completed_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, reviewID, at)
	return err
}
