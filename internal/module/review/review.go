// Package review is access reviews (user-flow ADM-6): a snapshot of who
// can do what in one organization, each line kept or removed by a
// reviewer, and the finished review stored.
package review

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/internal/storage"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/postgres"
)

type reviewModule struct {
	db     *postgres.DB
	repo   storage.ReviewRepository
	orgs   storage.OrganizationRepository
	iam    storage.IAMRepository
	audit  storage.AuditRepository
	notify module.Notification
	authz  module.Authorizer
	now    func() time.Time
	log    logger.Logger
}

func NewReviewModule(db *postgres.DB, repo storage.ReviewRepository, orgs storage.OrganizationRepository, iam storage.IAMRepository,
	audit storage.AuditRepository, notify module.Notification, authz module.Authorizer, now func() time.Time, log logger.Logger) module.Review {
	return &reviewModule{db: db, repo: repo, orgs: orgs, iam: iam, audit: audit, notify: notify, authz: authz, now: now, log: log}
}

var (
	errForbidden = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "forbidden", "you may not do this here")
	errClosed    = errors.Conflict("review_completed", "this review is already completed")
)

func (m *reviewModule) require(ctx context.Context, tx pgx.Tx, t *model.Tenant, actor model.Actor, resourceID string) error {
	if actor.Root {
		return nil
	}
	ok, _, err := m.authz.Check(ctx, tx, t.ID, actor.PrincipalID, constant.PermGrantManage, resourceID)
	if err != nil {
		return err
	}
	if !ok {
		return errForbidden
	}
	return nil
}

func (m *reviewModule) Start(ctx context.Context, t *model.Tenant, actor model.Actor, req request.StartReviewRequest, meta model.RequestMeta) (*response.AccessReview, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	reviewer := req.ReviewerPrincipalID
	if reviewer == "" {
		reviewer = actor.PrincipalID
	}
	var due *time.Time
	if req.DueDays > 0 {
		d := m.now().Add(time.Duration(req.DueDays) * 24 * time.Hour)
		due = &d
	}
	var id string
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		org, err := m.orgs.GetOrganization(ctx, tx, t.ID, req.OrganizationID)
		if err != nil {
			return err
		}
		if org == nil {
			return errors.NotFound("organization")
		}
		if err := m.require(ctx, tx, t, actor, org.ID); err != nil {
			return err
		}
		if reviewer != "" {
			ok, _, err := m.authz.Check(ctx, tx, t.ID, reviewer, constant.PermGrantManage, org.ID)
			if err != nil {
				return err
			}
			if !ok {
				return errors.Validation(map[string]string{"reviewer_principal_id": "must be able to manage grants in the organization"})
			}
		}
		if id, err = m.repo.CreateReview(ctx, tx, t.ID, org.ID, reviewer, due); err != nil {
			return err
		}
		n, err := m.repo.SnapshotGrants(ctx, tx, t.ID, id, org.ID)
		if err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "access_review.started", Result: model.AuditSuccess, OrganizationID: org.ID, ActorID: actor.PrincipalID,
			TargetType: "access_review", TargetID: id, Data: map[string]any{"items": n, "reviewer": reviewer},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "access_review.started", map[string]any{"review_id": id, "organization_id": org.ID, "reviewer_id": reviewer})
	})
	if err != nil {
		return nil, passThrough("start review", err)
	}
	m.notify.Wake()
	return m.Get(ctx, t, actor, id)
}

func (m *reviewModule) List(ctx context.Context, t *model.Tenant, actor model.Actor, organizationID string) ([]response.AccessReview, error) {
	if !postgres.IsUUID(organizationID) {
		return nil, errors.NotFound("organization")
	}
	out := []response.AccessReview{}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if err := m.require(ctx, tx, t, actor, organizationID); err != nil {
			return err
		}
		list, err := m.repo.ListReviews(ctx, tx, t.ID, organizationID)
		if err != nil {
			return err
		}
		for _, r := range list {
			n, err := m.repo.CountUndecided(ctx, tx, t.ID, r.ID)
			if err != nil {
				return err
			}
			v := toReview(r)
			v.Undecided = int(n)
			out = append(out, v)
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("list reviews", err)
	}
	return out, nil
}

// load gets a review the actor may see: Root, the reviewer, or someone
// who manages grants in the organization.
func (m *reviewModule) load(ctx context.Context, tx pgx.Tx, t *model.Tenant, actor model.Actor, id string) (*model.AccessReview, error) {
	r, err := m.repo.GetReview(ctx, tx, t.ID, id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.NotFound("review")
	}
	if actor.Root || actor.PrincipalID == r.ReviewerID {
		return r, nil
	}
	if err := m.require(ctx, tx, t, actor, r.OrganizationID); err != nil {
		return nil, errors.NotFound("review")
	}
	return r, nil
}

func (m *reviewModule) Get(ctx context.Context, t *model.Tenant, actor model.Actor, id string) (*response.AccessReview, error) {
	var out *response.AccessReview
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		r, err := m.load(ctx, tx, t, actor, id)
		if err != nil {
			return err
		}
		items, err := m.repo.ListItems(ctx, tx, t.ID, r.ID)
		if err != nil {
			return err
		}
		v := toReview(*r)
		v.Items = []response.AccessReviewItem{}
		for _, it := range items {
			if it.Decision == "" {
				v.Undecided++
			}
			v.Items = append(v.Items, response.AccessReviewItem{
				ID: it.ID, GrantID: it.GrantID, PrincipalID: it.PrincipalID, GroupID: it.GroupID, Who: it.Email, Role: it.Role,
				Resource: response.Resource{Type: it.ResourceType, ExternalID: it.ResourceID}, Effect: it.Effect,
				Decision: it.Decision, DecidedAt: it.DecidedAt, Gone: it.Gone,
			})
		}
		out = &v
		return nil
	})
	if err != nil {
		return nil, passThrough("get review", err)
	}
	return out, nil
}

func (m *reviewModule) Decide(ctx context.Context, t *model.Tenant, actor model.Actor, reviewID, itemID string, req request.ReviewDecisionRequest, meta model.RequestMeta) (*response.AccessReview, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		r, err := m.load(ctx, tx, t, actor, reviewID)
		if err != nil {
			return err
		}
		if r.Status != "open" {
			return errClosed
		}
		it, err := m.repo.LockItem(ctx, tx, t.ID, r.ID, itemID)
		if err != nil {
			return err
		}
		if it == nil {
			return errors.NotFound("item")
		}
		if req.Decision == "remove" && !it.Gone {
			// An ordinary grant removal, logged as part of the review.
			if _, err := m.iam.DeleteGrant(ctx, tx, t.ID, it.GrantID); err != nil {
				return err
			}
			if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "grant.removed", Result: model.AuditSuccess, ReasonCode: "access_review", OrganizationID: r.OrganizationID,
				ActorID: actor.PrincipalID, TargetType: "grant", TargetID: it.GrantID, Data: map[string]any{"review_id": r.ID},
				RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			}); err != nil {
				return err
			}
			if err := m.notify.Emit(ctx, tx, t.ID, "grant.removed", map[string]any{"grant_id": it.GrantID, "principal_id": it.PrincipalID, "review_id": r.ID}); err != nil {
				return err
			}
		}
		if err := m.repo.DecideItem(ctx, tx, t.ID, it.ID, req.Decision, now); err != nil {
			return err
		}
		left, err := m.repo.CountUndecided(ctx, tx, t.ID, r.ID)
		if err != nil {
			return err
		}
		if left == 0 {
			if err := m.repo.CompleteReview(ctx, tx, t.ID, r.ID, now); err != nil {
				return err
			}
			if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "access_review.completed", Result: model.AuditSuccess, OrganizationID: r.OrganizationID, ActorID: actor.PrincipalID,
				TargetType: "access_review", TargetID: r.ID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			}); err != nil {
				return err
			}
			return m.notify.Emit(ctx, tx, t.ID, "access_review.completed", map[string]any{"review_id": r.ID, "organization_id": r.OrganizationID})
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("decide", err)
	}
	m.notify.Wake()
	return m.Get(ctx, t, actor, reviewID)
}

func toReview(r model.AccessReview) response.AccessReview {
	return response.AccessReview{ID: r.ID, OrganizationID: r.OrganizationID, Status: r.Status, ReviewerID: r.ReviewerID, DueAt: r.DueAt, CompletedAt: r.CompletedAt, CreatedAt: r.CreatedAt}
}

func passThrough(operation string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsAppError(err); ok {
		return err
	}
	return fmt.Errorf("%s: %w", operation, err)
}
