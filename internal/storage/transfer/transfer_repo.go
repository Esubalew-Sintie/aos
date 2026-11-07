// Package transfer reads a whole tenant for export (HOST-6).
package transfer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/internal/storage"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/postgres"
)

type transferRepository struct {
	log logger.Logger
}

func NewTransferRepository(log logger.Logger) storage.TransferRepository {
	return &transferRepository{log: log}
}

func (r *transferRepository) CountUsers(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error) {
	var n int64
	err := tx.QueryRow(ctx, `SELECT count(*) FROM aos.principals WHERE tenant_id = $1 AND kind <> 'support'`, tenantID).Scan(&n)
	return n, err
}

func (r *transferRepository) SetMachineFields(ctx context.Context, tx pgx.Tx, tenantID, principalID, purpose, ownerID string) error {
	_, err := tx.Exec(ctx, `UPDATE aos.principals SET purpose = NULLIF($3, ''), owner_principal_id = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantID, principalID, purpose, postgres.NullString(ownerID))
	return err
}

func (r *transferRepository) SetMFAPolicy(ctx context.Context, tx pgx.Tx, tenantID, policy string) error {
	_, err := tx.Exec(ctx, `UPDATE aos.tenants SET mfa_policy = $2 WHERE id = $1`, tenantID, policy)
	return err
}

func (r *transferRepository) ReadArchive(ctx context.Context, tx pgx.Tx, tenantID string) (*model.Archive, error) {
	a := &model.Archive{Format: "aos-archive/1"}
	var defaultRole *string
	err := tx.QueryRow(ctx, `
		SELECT t.slug, t.kind, t.signup_policy, t.signup_domains, t.org_creation_policy, t.mfa_policy, ro.name, t.session_idle_seconds, t.session_absolute_seconds
		FROM aos.tenants t LEFT JOIN aos.roles ro ON ro.tenant_id = t.id AND ro.id = t.default_role_id WHERE t.id = $1`, tenantID).Scan(
		&a.TenantSlug, &a.Kind, &a.Settings.SignupPolicy, &a.Settings.SignupDomains, &a.Settings.OrgCreationPolicy, &a.Settings.MFAPolicy,
		&defaultRole, &a.Settings.SessionIdleSeconds, &a.Settings.SessionAbsoluteSeconds)
	if err != nil {
		return nil, fmt.Errorf("archive tenant: %w", err)
	}
	if defaultRole != nil {
		a.Settings.DefaultRole = *defaultRole
	}

	collect := func(name string, query string, scan func(pgx.CollectableRow) error, args ...any) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("archive %s: %w", name, err)
		}
		defer rows.Close()
		for rows.Next() {
			if err := scan(rows); err != nil {
				return fmt.Errorf("archive %s: %w", name, err)
			}
		}
		return rows.Err()
	}

	if err := collect("permissions", `
		SELECT name, COALESCE(description, ''), source, COALESCE(step_up_seconds, 0), needs_approval
		FROM aos.permissions WHERE tenant_id = $1 AND retired_at IS NULL ORDER BY name`, func(row pgx.CollectableRow) error {
		var p model.ArchivePermission
		if err := row.Scan(&p.Name, &p.Description, &p.Source, &p.StepUpSeconds, &p.NeedsApproval); err != nil {
			return err
		}
		a.Permissions = append(a.Permissions, p)
		return nil
	}, tenantID); err != nil {
		return nil, err
	}

	if err := collect("roles", `
		SELECT ro.name, COALESCE(ro.description, ''), ro.source,
		       COALESCE((SELECT array_agg(rp.pattern ORDER BY rp.pattern) FROM aos.role_permissions rp WHERE rp.tenant_id = ro.tenant_id AND rp.role_id = ro.id), '{}')
		FROM aos.roles ro WHERE ro.tenant_id = $1 AND ro.organization_id IS NULL ORDER BY ro.name`, func(row pgx.CollectableRow) error {
		var ro model.ArchiveRole
		if err := row.Scan(&ro.Name, &ro.Description, &ro.Source, &ro.Patterns); err != nil {
			return err
		}
		a.Roles = append(a.Roles, ro)
		return nil
	}, tenantID); err != nil {
		return nil, err
	}

	// Resources, parents before children; the root is not exported.
	if err := collect("resources", `
		SELECT re.type, re.external_id, p.type, p.external_id, COALESCE(re.display_name, '')
		FROM aos.resources re
		JOIN aos.resources p ON p.tenant_id = re.tenant_id AND p.id = re.parent_id
		WHERE re.tenant_id = $1 AND re.deleted_at IS NULL
		ORDER BY (SELECT max(depth) FROM aos.resource_ancestors x WHERE x.tenant_id = re.tenant_id AND x.resource_id = re.id), re.created_at`, func(row pgx.CollectableRow) error {
		var re model.ArchiveResource
		if err := row.Scan(&re.Type, &re.ID, &re.ParentType, &re.ParentID, &re.DisplayName); err != nil {
			return err
		}
		a.Resources = append(a.Resources, re)
		return nil
	}, tenantID); err != nil {
		return nil, err
	}

	if err := collect("organizations", `
		SELECT re.external_id, o.slug, o.name, o.mfa_required, COALESCE(o.session_max_seconds, 0), COALESCE(o.allowed_auth_methods, '{}'),
		       COALESCE(o.ip_allowlist::text[], '{}'), o.enforce_sso, COALESCE(o.break_glass_principal_id::text, '')
		FROM aos.organizations o JOIN aos.resources re ON re.tenant_id = o.tenant_id AND re.id = o.resource_id
		WHERE o.tenant_id = $1 AND o.status = 'active' ORDER BY o.created_at`, func(row pgx.CollectableRow) error {
		var o model.ArchiveOrganization
		if err := row.Scan(&o.ResourceID, &o.Slug, &o.Name, &o.Policies.MFARequired, &o.Policies.SessionMaxSeconds, &o.Policies.AllowedAuthMethods,
			&o.Policies.IPAllowlist, &o.Policies.EnforceSSO, &o.Policies.BreakGlassPrincipalID); err != nil {
			return err
		}
		a.Organizations = append(a.Organizations, o)
		return nil
	}, tenantID); err != nil {
		return nil, err
	}

	index := map[string]int{}
	if err := collect("principals", `
		SELECT p.id::text, p.kind, p.status, COALESCE(p.display_name, ''), COALESCE(p.purpose, ''), COALESCE(p.owner_principal_id::text, ''),
		       COALESCE(u.email::text, ''), COALESCE(u.name, ''), u.email_verified_at IS NOT NULL,
		       COALESCE((SELECT pw.hash FROM aos.passwords pw WHERE pw.tenant_id = p.tenant_id AND pw.principal_id = p.id AND pw.status = 'active'), ''),
		       f.secret_encrypted, COALESCE(f.data_key_id::text, '')
		FROM aos.principals p
		LEFT JOIN aos.users u ON u.tenant_id = p.tenant_id AND u.principal_id = p.id
		LEFT JOIN aos.totp_factors f ON f.tenant_id = p.tenant_id AND f.principal_id = p.id AND f.confirmed_at IS NOT NULL
		WHERE p.tenant_id = $1 AND p.kind <> 'support' AND p.status <> 'deleted'
		ORDER BY p.created_at`, func(row pgx.CollectableRow) error {
		var p model.ArchivePrincipal
		if err := row.Scan(&p.OldID, &p.Kind, &p.Status, &p.DisplayName, &p.Purpose, &p.OwnerOldID, &p.Email, &p.Name, &p.EmailVerified,
			&p.PasswordHash, &p.TOTPEncrypted, &p.TOTPKeyID); err != nil {
			return err
		}
		index[p.OldID] = len(a.Principals)
		a.Principals = append(a.Principals, p)
		return nil
	}, tenantID); err != nil {
		return nil, err
	}

	if err := collect("recovery codes", `
		SELECT principal_id::text, code_hash FROM aos.recovery_codes WHERE tenant_id = $1 AND used_at IS NULL`, func(row pgx.CollectableRow) error {
		var id string
		var h []byte
		if err := row.Scan(&id, &h); err != nil {
			return err
		}
		if i, ok := index[id]; ok {
			a.Principals[i].RecoveryCodes = append(a.Principals[i].RecoveryCodes, h)
		}
		return nil
	}, tenantID); err != nil {
		return nil, err
	}

	if err := collect("passkeys", `
		SELECT principal_id::text, credential_id, public_key, sign_count, transports, aaguid, backup_eligible, backed_up, COALESCE(name, '')
		FROM aos.passkeys WHERE tenant_id = $1`, func(row pgx.CollectableRow) error {
		var id string
		var k model.ArchivePasskey
		var aaguid *[16]byte
		if err := row.Scan(&id, &k.CredentialID, &k.PublicKey, &k.SignCount, &k.Transports, &aaguid, &k.BackupEligible, &k.BackedUp, &k.Name); err != nil {
			return err
		}
		if aaguid != nil {
			k.AAGUID = aaguid[:]
		}
		if i, ok := index[id]; ok {
			a.Principals[i].Passkeys = append(a.Principals[i].Passkeys, k)
		}
		return nil
	}, tenantID); err != nil {
		return nil, err
	}

	if err := collect("groups", `
		SELECT g.id::text, g.name, COALESCE(re.external_id, ''),
		       COALESCE((SELECT array_agg(gm.principal_id::text) FROM aos.group_members gm WHERE gm.tenant_id = g.tenant_id AND gm.group_id = g.id), '{}')
		FROM aos.groups g LEFT JOIN aos.resources re ON re.tenant_id = g.tenant_id AND re.id = g.organization_id
		WHERE g.tenant_id = $1 ORDER BY g.created_at`, func(row pgx.CollectableRow) error {
		var g model.ArchiveGroup
		if err := row.Scan(&g.OldID, &g.Name, &g.Organization, &g.Members); err != nil {
			return err
		}
		a.Groups = append(a.Groups, g)
		return nil
	}, tenantID); err != nil {
		return nil, err
	}

	if err := collect("grants", `
		SELECT COALESCE(g.principal_id::text, ''), COALESCE(g.group_id::text, ''), ro.name, re.type, re.external_id, g.effect,
		       COALESCE(g.condition, ''), g.expires_at, g.source, COALESCE(g.reason, '')
		FROM aos.grants g
		JOIN aos.roles ro ON ro.tenant_id = g.tenant_id AND ro.id = g.role_id
		JOIN aos.resources re ON re.tenant_id = g.tenant_id AND re.id = g.resource_id
		LEFT JOIN aos.principals p ON p.tenant_id = g.tenant_id AND p.id = g.principal_id
		WHERE g.tenant_id = $1 AND (p.id IS NULL OR p.kind <> 'support') AND re.deleted_at IS NULL
		ORDER BY g.created_at`, func(row pgx.CollectableRow) error {
		var gr model.ArchiveGrant
		if err := row.Scan(&gr.PrincipalOldID, &gr.GroupOldID, &gr.Role, &gr.ResourceType, &gr.ResourceID, &gr.Effect, &gr.Condition, &gr.ExpiresAt, &gr.Source, &gr.Reason); err != nil {
			return err
		}
		a.Grants = append(a.Grants, gr)
		return nil
	}, tenantID); err != nil {
		return nil, err
	}

	var head []byte
	err = tx.QueryRow(ctx, `SELECT last_seq, last_hash FROM aos.audit_heads WHERE tenant_id = $1`, tenantID).Scan(&a.AuditSeq, &head)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("archive audit head: %w", err)
	}
	a.AuditHead = hex.EncodeToString(head)
	return a, nil
}
