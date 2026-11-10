// Package transfer moves people and whole tenants between homes:
// importing users with their password hashes (SET-4 step 6), and an
// encrypted archive of a tenant that another AOS can read (HOST-6).
package transfer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/internal/storage"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/postgres"
	"github.com/flash-software-technology/aos/platform/secret"
)

const archiveFormat = "aos-archive/1"

type transferModule struct {
	db     *postgres.DB
	repo   storage.TransferRepository
	users  storage.AuthRepository
	iam    storage.IAMRepository
	orgs   storage.OrganizationRepository
	tenant storage.TenantRepository
	audit  storage.AuditRepository
	keys   module.KeyRing
	now    func() time.Time
	log    logger.Logger
}

func NewTransferModule(db *postgres.DB, repo storage.TransferRepository, users storage.AuthRepository, iam storage.IAMRepository,
	orgs storage.OrganizationRepository, tenant storage.TenantRepository, audit storage.AuditRepository, keys module.KeyRing,
	now func() time.Time, log logger.Logger) module.Transfer {
	return &transferModule{db: db, repo: repo, users: users, iam: iam, orgs: orgs, tenant: tenant, audit: audit, keys: keys, now: now, log: log}
}

var (
	errNotEmpty    = errors.Conflict("tenant_not_empty", "an archive can only be imported into a tenant with no people yet")
	errBadArchive  = errors.New(errors.ErrorTypeBadRequest, http.StatusBadRequest, "invalid_archive", "the archive could not be read. check the passphrase")
	errKindDiffers = errors.Conflict("kind_differs", "the archive comes from a tenant of another kind")
)

func totpContext(tenantID, principalID string) []byte {
	return []byte("totp:" + tenantID + ":" + principalID)
}

// ---------------------------------------------------------------------
// Importing users
// ---------------------------------------------------------------------

func (m *transferModule) ImportUsers(ctx context.Context, t *model.Tenant, req request.ImportUsersRequest, meta model.RequestMeta) (*response.ImportResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	out := &response.ImportResult{Skipped: []response.ImportSkip{}, IDs: map[string]string{}}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		seen := map[string]bool{}
		for _, u := range req.Users {
			skip := func(reason string) {
				out.Skipped = append(out.Skipped, response.ImportSkip{Email: u.Email, Reason: reason})
			}
			switch {
			case u.Email == "" || seen[u.Email]:
				skip("missing or repeated address")
				continue
			case u.PasswordHash != "" && !secret.IsSupportedHash(u.PasswordHash):
				skip("password hash format not supported")
				continue
			}
			seen[u.Email] = true
			existing, err := m.users.FindUserByEmail(ctx, tx, t.ID, u.Email)
			if err != nil {
				return err
			}
			if existing != nil {
				skip("an account with this address exists")
				continue
			}
			// Roles are checked before anything is written for this person.
			type grant struct{ roleID, resourceID string }
			var grants []grant
			bad := ""
			for _, r := range u.Roles {
				roleID, _, err := m.iam.GetRoleByName(ctx, tx, t.ID, r.Role)
				if err != nil {
					return err
				}
				resourceID, _, err := m.iam.FindResource(ctx, tx, t.ID, model.ResourceRef{Type: r.Resource.Type, ID: r.Resource.ID})
				if err != nil {
					return err
				}
				if roleID == "" || resourceID == "" {
					bad = "role " + r.Role + " or its resource does not exist"
					break
				}
				grants = append(grants, grant{roleID, resourceID})
			}
			if bad != "" {
				skip(bad)
				continue
			}
			id, err := m.users.CreateUser(ctx, tx, t.ID, u.Email, u.Name)
			if err != nil {
				return err
			}
			if u.EmailVerified {
				if err := m.users.MarkEmailVerified(ctx, tx, t.ID, id, now); err != nil {
					return err
				}
			}
			if u.PasswordHash != "" {
				if err := m.users.SetPassword(ctx, tx, t.ID, id, u.PasswordHash); err != nil {
					return err
				}
			}
			for _, g := range grants {
				if _, err := m.iam.CreateGrant(ctx, tx, t.ID, model.NewGrant{
					PrincipalID: id, RoleID: g.roleID, ResourceID: g.resourceID, Effect: constant.EffectAllow, Source: "manual", Reason: "imported",
				}); err != nil {
					return err
				}
			}
			out.Created++
			out.IDs[u.Email] = id
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "users.imported", Result: model.AuditSuccess, Data: map[string]any{"created": out.Created, "skipped": len(out.Skipped)},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	if err != nil {
		return nil, passThrough("import users", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// The archive
// ---------------------------------------------------------------------

type sealedArchive struct {
	Format string `json:"format"`
	Salt   string `json:"salt"`
	Data   string `json:"data"`
}

func archiveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 2, 32)
}

func (m *transferModule) Export(ctx context.Context, t *model.Tenant, req request.ExportRequest, meta model.RequestMeta) (*response.Archive, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var a *model.Archive
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		var err error
		if a, err = m.repo.ReadArchive(ctx, tx, t.ID); err != nil {
			return err
		}
		// Seeds leave encrypted under this tenant's keys; inside the sealed
		// archive they are plain, and the new home seals them again.
		for i := range a.Principals {
			p := &a.Principals[i]
			if len(p.TOTPEncrypted) == 0 {
				continue
			}
			key, err := m.keys.DataKeyByID(ctx, tx, t.ID, p.TOTPKeyID)
			if err != nil {
				return err
			}
			if p.TOTPSecret, err = secret.Open(key, p.TOTPEncrypted, totpContext(t.ID, p.OldID)); err != nil {
				return fmt.Errorf("open totp seed: %w", err)
			}
		}
		a.ExportedAt = m.now()
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "tenant.exported", Result: model.AuditSuccess, Data: map[string]any{"principals": len(a.Principals)},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	if err != nil {
		return nil, passThrough("export", err)
	}
	plain, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	if _, err := zw.Write(plain); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	sealed, err := secret.Seal(archiveKey(req.Passphrase, salt), zipped.Bytes(), []byte(archiveFormat))
	if err != nil {
		return nil, err
	}
	envelope, _ := json.Marshal(sealedArchive{Format: archiveFormat, Salt: base64.StdEncoding.EncodeToString(salt), Data: base64.StdEncoding.EncodeToString(sealed)})
	return &response.Archive{
		Format: archiveFormat, Archive: base64.StdEncoding.EncodeToString(envelope), CreatedAt: a.ExportedAt,
		Counts: map[string]int{"principals": len(a.Principals), "roles": len(a.Roles), "permissions": len(a.Permissions),
			"resources": len(a.Resources), "organizations": len(a.Organizations), "groups": len(a.Groups), "grants": len(a.Grants)},
	}, nil
}

// OpenArchive reads an archive with its passphrase.
func OpenArchive(archive, passphrase string) (*model.Archive, error) {
	raw, err := base64.StdEncoding.DecodeString(archive)
	if err != nil {
		return nil, errBadArchive
	}
	var env sealedArchive
	if err := json.Unmarshal(raw, &env); err != nil || env.Format != archiveFormat {
		return nil, errBadArchive
	}
	salt, err1 := base64.StdEncoding.DecodeString(env.Salt)
	data, err2 := base64.StdEncoding.DecodeString(env.Data)
	if err1 != nil || err2 != nil {
		return nil, errBadArchive
	}
	zipped, err := secret.Open(archiveKey(passphrase, salt), data, []byte(archiveFormat))
	if err != nil {
		return nil, errBadArchive
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, errBadArchive
	}
	plain, err := io.ReadAll(io.LimitReader(zr, 512<<20))
	if err != nil {
		return nil, errBadArchive
	}
	var a model.Archive
	if err := json.Unmarshal(plain, &a); err != nil || a.Format != archiveFormat {
		return nil, errBadArchive
	}
	return &a, nil
}

func (m *transferModule) Import(ctx context.Context, t *model.Tenant, req request.ImportArchiveRequest, meta model.RequestMeta) (*response.ArchiveImport, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	a, err := OpenArchive(req.Archive, req.Passphrase)
	if err != nil {
		return nil, err
	}
	if a.Kind != t.Kind {
		return nil, errKindDiffers
	}
	now := m.now()
	counts := map[string]int{}
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		n, err := m.repo.CountUsers(ctx, tx, t.ID)
		if err != nil {
			return err
		}
		if n > 0 {
			return errNotEmpty
		}
		// Permissions and roles.
		for _, p := range a.Permissions {
			if _, err := m.iam.UpsertPermission(ctx, tx, t.ID, p.Name, p.Description, p.Source); err != nil {
				return err
			}
			if err := m.iam.SetPermissionStepUp(ctx, tx, t.ID, p.Name, p.StepUpSeconds); err != nil {
				return err
			}
			if err := m.iam.SetPermissionNeedsApproval(ctx, tx, t.ID, p.Name, p.NeedsApproval); err != nil {
				return err
			}
		}
		roles := map[string]string{}
		for _, r := range a.Roles {
			id, _, err := m.iam.UpsertRole(ctx, tx, t.ID, r.Name, r.Description, r.Source)
			if err != nil {
				return err
			}
			if r.Name != constant.RoleOwner {
				if err := m.iam.ReplaceRolePermissions(ctx, tx, t.ID, id, r.Patterns); err != nil {
					return err
				}
			}
			roles[r.Name] = id
		}
		counts["permissions"], counts["roles"] = len(a.Permissions), len(a.Roles)

		// The resource tree, parents first.
		find := func(typ, id string) (string, error) {
			rid, _, err := m.iam.FindResource(ctx, tx, t.ID, model.ResourceRef{Type: typ, ID: id})
			return rid, err
		}
		for _, r := range a.Resources {
			parent, err := find(r.ParentType, r.ParentID)
			if err != nil {
				return err
			}
			if parent == "" {
				return fmt.Errorf("import: the parent of %s %s is missing", r.Type, r.ID)
			}
			if err := m.iam.EnsureResourceType(ctx, tx, t.ID, r.Type); err != nil {
				return err
			}
			if _, err := m.iam.CreateResource(ctx, tx, t.ID, model.ResourceRef{Type: r.Type, ID: r.ID}, parent, r.DisplayName); err != nil {
				return err
			}
		}
		counts["resources"] = len(a.Resources)

		// People.
		ids := map[string]string{}
		for _, p := range a.Principals {
			var id string
			switch p.Kind {
			case constant.PrincipalKindUser:
				id, err = m.users.CreateUser(ctx, tx, t.ID, p.Email, p.Name)
				if err != nil {
					return err
				}
				if p.EmailVerified {
					if err := m.users.MarkEmailVerified(ctx, tx, t.ID, id, now); err != nil {
						return err
					}
				}
				if p.PasswordHash != "" {
					if err := m.users.SetPassword(ctx, tx, t.ID, id, p.PasswordHash); err != nil {
						return err
					}
				}
			case constant.PrincipalKindGuest:
				if id, err = m.users.CreateGuest(ctx, tx, t.ID, p.DisplayName); err != nil {
					return err
				}
			default:
				if err := tx.QueryRow(ctx, `INSERT INTO aos.principals (tenant_id, kind, display_name) VALUES ($1, $2, NULLIF($3, '')) RETURNING id::text`,
					t.ID, p.Kind, p.DisplayName).Scan(&id); err != nil {
					return fmt.Errorf("import principal: %w", err)
				}
			}
			ids[p.OldID] = id
			if p.Status != constant.PrincipalActive {
				if err := m.users.SetPrincipalStatus(ctx, tx, t.ID, id, p.Status, "imported", now); err != nil {
					return err
				}
			}
			if len(p.TOTPSecret) > 0 {
				keyID, key, err := m.keys.DataKey(ctx, tx, t.ID)
				if err != nil {
					return err
				}
				sealed, err := secret.Seal(key, p.TOTPSecret, totpContext(t.ID, id))
				if err != nil {
					return err
				}
				factorID, err := m.users.CreateTOTP(ctx, tx, t.ID, id, sealed, keyID)
				if err != nil {
					return err
				}
				if err := m.users.ConfirmTOTP(ctx, tx, t.ID, factorID, now); err != nil {
					return err
				}
			}
			if len(p.RecoveryCodes) > 0 {
				if err := m.users.ReplaceRecoveryCodes(ctx, tx, t.ID, id, p.RecoveryCodes); err != nil {
					return err
				}
			}
			// A passkey is bound to its domain; it works only if the
			// application keeps its address.
			for _, k := range p.Passkeys {
				if _, err := m.users.CreatePasskey(ctx, tx, t.ID, model.Passkey{
					PrincipalID: id, CredentialID: k.CredentialID, PublicKey: k.PublicKey, SignCount: k.SignCount, Transports: k.Transports,
					AAGUID: k.AAGUID, BackupEligible: k.BackupEligible, BackedUp: k.BackedUp, Name: k.Name,
				}); err != nil {
					return err
				}
			}
		}
		for _, p := range a.Principals {
			if p.Purpose != "" || p.OwnerOldID != "" {
				if err := m.repo.SetMachineFields(ctx, tx, t.ID, ids[p.OldID], p.Purpose, ids[p.OwnerOldID]); err != nil {
					return err
				}
			}
		}
		counts["principals"] = len(a.Principals)

		// Organizations, with their policies.
		for _, o := range a.Organizations {
			rid, err := find(constant.ResourceTypeOrganization, o.ResourceID)
			if err != nil {
				return err
			}
			if rid == "" {
				return fmt.Errorf("import: organization node %s is missing", o.ResourceID)
			}
			if err := m.orgs.CreateOrganization(ctx, tx, t.ID, rid, o.Slug, o.Name, ""); err != nil {
				return err
			}
			o.Policies.BreakGlassPrincipalID = ids[o.Policies.BreakGlassPrincipalID]
			if err := m.orgs.SetPolicies(ctx, tx, t.ID, rid, o.Policies); err != nil {
				return err
			}
		}
		counts["organizations"] = len(a.Organizations)

		groups := map[string]string{}
		for _, g := range a.Groups {
			orgID := ""
			if g.Organization != "" {
				if orgID, err = find(constant.ResourceTypeOrganization, g.Organization); err != nil {
					return err
				}
			}
			gid, err := m.iam.UpsertGroup(ctx, tx, t.ID, g.Name, orgID)
			if err != nil {
				return err
			}
			groups[g.OldID] = gid
			for _, member := range g.Members {
				if newID := ids[member]; newID != "" {
					if err := m.iam.AddGroupMember(ctx, tx, t.ID, gid, newID); err != nil {
						return err
					}
				}
			}
		}
		counts["groups"] = len(a.Groups)

		for _, g := range a.Grants {
			roleID := roles[g.Role]
			if roleID == "" {
				roleID, _, _ = m.iam.GetRoleByName(ctx, tx, t.ID, g.Role)
			}
			resourceID, err := find(g.ResourceType, g.ResourceID)
			if err != nil {
				return err
			}
			if roleID == "" || resourceID == "" {
				continue
			}
			ng := model.NewGrant{RoleID: roleID, ResourceID: resourceID, Effect: g.Effect, Condition: g.Condition, ExpiresAt: g.ExpiresAt, Source: g.Source, Reason: g.Reason}
			if g.PrincipalOldID != "" {
				if ng.PrincipalID = ids[g.PrincipalOldID]; ng.PrincipalID == "" {
					continue
				}
			} else if ng.GroupID = groups[g.GroupOldID]; ng.GroupID == "" {
				continue
			}
			if _, err := m.iam.CreateGrant(ctx, tx, t.ID, ng); err != nil {
				return err
			}
			counts["grants"]++
		}

		// Settings.
		s := model.TenantSettings{Name: t.Name, AppURL: t.AppURL, SignupPolicy: a.Settings.SignupPolicy, SignupDomains: a.Settings.SignupDomains,
			OrgCreationPolicy: a.Settings.OrgCreationPolicy, DefaultRoleID: roles[a.Settings.DefaultRole],
			SessionIdle: time.Duration(a.Settings.SessionIdleSeconds) * time.Second, SessionAbsolute: time.Duration(a.Settings.SessionAbsoluteSeconds) * time.Second}
		if s.SignupDomains == nil {
			s.SignupDomains = []string{}
		}
		if err := m.tenant.UpdateTenantSettings(ctx, tx, t.ID, s); err != nil {
			return err
		}
		if err := m.repo.SetMFAPolicy(ctx, tx, t.ID, a.Settings.MFAPolicy); err != nil {
			return err
		}
		// The new chain records where the old one ended.
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "tenant.imported", Result: model.AuditSuccess,
			Data:      map[string]any{"from_tenant": a.TenantSlug, "previous_audit_seq": a.AuditSeq, "previous_audit_head": a.AuditHead, "counts": counts},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	if err != nil {
		return nil, passThrough("import archive", err)
	}
	return &response.ArchiveImport{Counts: counts}, nil
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
