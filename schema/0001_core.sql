-- =====================================================================
-- AOS v3 core schema. Design draft, 5 November 2026.
--
-- Postgres 15 or newer. Everything lives in the "aos" schema.
-- The same file is used in every mode: hosted, or the developer's own
-- database. The hosted-only tables are in platform.sql.
--
-- Rules this file follows (see README.md):
--   1. Every table carries tenant_id. Foreign keys include it, so a row
--      in one tenant can never point at a row in another.
--   2. Row-level security is on for every table (section 12).
--   3. Secrets are stored as a hash, or encrypted. Never in clear.
--   4. Closed sets are text with a CHECK, not Postgres enum types.
--   5. "Who did it" columns (created_by and similar) are plain ids with
--      no foreign key, so erasing a person never blocks or rewrites history.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS citext;
CREATE SCHEMA IF NOT EXISTS aos;

-- ---------------------------------------------------------------------
-- 0. Migration bookkeeping
-- ---------------------------------------------------------------------

CREATE TABLE aos.schema_migrations (
    version     integer     PRIMARY KEY,
    name        text        NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 1. Tenants and their settings
-- ---------------------------------------------------------------------

-- One row per tenant: one application's isolated pool of users,
-- settings and keys. The developer's own database usually holds one.
-- The hosted service holds many.
CREATE TABLE aos.tenants (
    id                        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug                      text        NOT NULL UNIQUE,
    name                      text        NOT NULL,
    kind                      text        NOT NULL DEFAULT 'single'
                              CHECK (kind IN ('single', 'multi')),
    environment               text        NOT NULL DEFAULT 'production'
                              CHECK (environment IN ('development', 'staging', 'production')),
    status                    text        NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'restricted', 'suspended', 'deleted')),
    -- Sign-up: open to all, by invitation only, or listed email domains only (REG-1).
    signup_policy             text        NOT NULL DEFAULT 'open'
                              CHECK (signup_policy IN ('open', 'invite_only', 'domains')),
    signup_domains            text[]      NOT NULL DEFAULT '{}',
    -- Who may create an organization (WHO-4).
    org_creation_policy       text        NOT NULL DEFAULT 'self_service'
                              CHECK (org_creation_policy IN ('self_service', 'admin_only', 'application')),
    -- Role every new user receives on the root, or null for none (WHO-6).
    default_role_id           uuid,
    mfa_policy                text        NOT NULL DEFAULT 'optional'
                              CHECK (mfa_policy IN ('optional', 'required')),
    allowed_auth_methods      text[]      NOT NULL DEFAULT '{password}',
    session_idle_seconds      integer     NOT NULL DEFAULT 604800,   -- 7 days
    session_absolute_seconds  integer     NOT NULL DEFAULT 2592000,  -- 30 days
    -- The top of this tenant's resource tree. Set right after creation.
    root_resource_id          uuid,
    settings                  jsonb       NOT NULL DEFAULT '{}',
    created_at                timestamptz NOT NULL DEFAULT now(),
    deleted_at                timestamptz,
    purge_after               timestamptz
);

-- Hostnames that belong to a tenant: the address its AOS API answers on,
-- or the application's own hostname when there is a tenant per customer.
-- Stored in lower case, so lookups need no case-insensitive type.
CREATE TABLE aos.tenant_hostnames (
    hostname     text        PRIMARY KEY CHECK (hostname = lower(hostname)),
    tenant_id    uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    purpose      text        NOT NULL CHECK (purpose IN ('api', 'application')),
    dns_value    text,
    verified_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tenant_hostnames_tenant ON aos.tenant_hostnames (tenant_id);

-- Web addresses allowed to call this tenant's API from a browser (SYS-2).
CREATE TABLE aos.allowed_origins (
    tenant_id   uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    origin      text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, origin)
);

-- The tenant's own keys (HOST-3). A publishable key only names the tenant.
-- A secret key lets the application's backend call the API.
CREATE TABLE aos.tenant_keys (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    kind          text        NOT NULL CHECK (kind IN ('publishable', 'secret')),
    public_id     text        NOT NULL UNIQUE,
    secret_hash   bytea,
    created_by    uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,
    revoked_at    timestamptz,
    last_used_at  timestamptz,
    CHECK ((kind = 'secret') = (secret_hash IS NOT NULL))
);
CREATE INDEX tenant_keys_tenant ON aos.tenant_keys (tenant_id);

-- Data keys for envelope encryption. Each is wrapped by a master key that
-- lives outside the database, in the environment or a key service.
CREATE TABLE aos.data_keys (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    wrapped_key     bytea       NOT NULL,
    master_key_ref  text        NOT NULL,
    status          text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    retired_at      timestamptz,
    UNIQUE (tenant_id, id)
);

-- Keys that sign session tokens and access tokens. Public halves are published.
CREATE TABLE aos.signing_keys (
    id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    kid                    text        NOT NULL,
    algorithm              text        NOT NULL DEFAULT 'EdDSA',
    public_key             bytea       NOT NULL,
    private_key_encrypted  bytea       NOT NULL,
    data_key_id            uuid        NOT NULL,
    status                 text        NOT NULL DEFAULT 'next'
                           CHECK (status IN ('next', 'active', 'retiring', 'retired')),
    created_at             timestamptz NOT NULL DEFAULT now(),
    activated_at           timestamptz,
    retired_at             timestamptz,
    UNIQUE (tenant_id, kid),
    FOREIGN KEY (tenant_id, data_key_id) REFERENCES aos.data_keys (tenant_id, id)
);

-- Where email, SMS and WhatsApp messages are sent through.
CREATE TABLE aos.message_providers (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    channel           text        NOT NULL CHECK (channel IN ('email', 'sms', 'whatsapp')),
    provider          text        NOT NULL,
    from_address      text,
    config_encrypted  bytea,
    data_key_id       uuid,
    is_default        boolean     NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, data_key_id) REFERENCES aos.data_keys (tenant_id, id)
);
CREATE UNIQUE INDEX message_providers_default
    ON aos.message_providers (tenant_id, channel) WHERE is_default;

-- ---------------------------------------------------------------------
-- 2. Principals: anything that can act
-- ---------------------------------------------------------------------

-- A user, a guest, a service account, an AI agent, or a temporary
-- support principal created for approved hosted support (HOST-8).
CREATE TABLE aos.principals (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    kind                text        NOT NULL
                        CHECK (kind IN ('user', 'guest', 'service', 'agent', 'support')),
    status              text        NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'suspended', 'deleted')),
    display_name        text,
    -- Service accounts and agents have an owner and a stated purpose.
    owner_principal_id  uuid,
    purpose             text,
    status_reason       text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    suspended_at        timestamptz,
    deleted_at          timestamptz,
    purge_after         timestamptz,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, owner_principal_id) REFERENCES aos.principals (tenant_id, id)
);
CREATE INDEX principals_tenant_kind ON aos.principals (tenant_id, kind, status);

-- The person behind a principal of kind 'user'.
CREATE TABLE aos.users (
    principal_id       uuid        PRIMARY KEY,
    tenant_id          uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    email              citext,
    email_verified_at  timestamptz,
    phone              text,
    phone_verified_at  timestamptz,
    name               text,
    locale             text,
    -- 0 nothing verified, 1 email, 2 phone, 3 identity document.
    assurance_level    smallint    NOT NULL DEFAULT 0,
    profile            jsonb       NOT NULL DEFAULT '{}',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    CHECK (email IS NOT NULL OR phone IS NOT NULL)
);
-- The same email can be a different account in another tenant, never in the same one.
CREATE UNIQUE INDEX users_email ON aos.users (tenant_id, email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX users_phone ON aos.users (tenant_id, phone) WHERE phone IS NOT NULL;

-- ---------------------------------------------------------------------
-- 3. The resource tree and organizations
-- ---------------------------------------------------------------------

CREATE TABLE aos.resource_types (
    tenant_id        uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    name             text        NOT NULL,
    allowed_parents  text[]      NOT NULL DEFAULT '{}',
    source           text        NOT NULL DEFAULT 'code' CHECK (source IN ('system', 'code', 'portal')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name)
);

-- A node in the tree the application defines. The tenant root, each
-- organization, and anything else people are given access to.
CREATE TABLE aos.resources (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    type          text        NOT NULL,
    -- The application's own id for this object.
    external_id   text        NOT NULL,
    parent_id     uuid,
    display_name  text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    deleted_at    timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, type, external_id),
    FOREIGN KEY (tenant_id, type) REFERENCES aos.resource_types (tenant_id, name),
    FOREIGN KEY (tenant_id, parent_id) REFERENCES aos.resources (tenant_id, id) ON DELETE CASCADE
);
-- Exactly one root per tenant.
CREATE UNIQUE INDEX resources_one_root ON aos.resources (tenant_id) WHERE parent_id IS NULL;
CREATE INDEX resources_parent ON aos.resources (tenant_id, parent_id);

-- Closure table: one row for every (node, ancestor) pair, the node itself
-- included at depth 0. "All ancestors of X" and "everything under X" are
-- both a single indexed lookup, with no recursion. Works in any SQL database.
CREATE TABLE aos.resource_ancestors (
    tenant_id    uuid    NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    resource_id  uuid    NOT NULL,
    ancestor_id  uuid    NOT NULL,
    depth        integer NOT NULL CHECK (depth >= 0),
    PRIMARY KEY (resource_id, ancestor_id),
    FOREIGN KEY (tenant_id, resource_id) REFERENCES aos.resources (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, ancestor_id) REFERENCES aos.resources (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX resource_ancestors_down ON aos.resource_ancestors (tenant_id, ancestor_id);

-- An organization is a resource with extra settings (ORG-1, ENT-7).
CREATE TABLE aos.organizations (
    resource_id               uuid        PRIMARY KEY,
    tenant_id                 uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    slug                      text        NOT NULL,
    name                      text        NOT NULL,
    status                    text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
    -- Policies. They can only make the tenant's rules stricter.
    mfa_required              boolean     NOT NULL DEFAULT false,
    session_max_seconds       integer,
    allowed_auth_methods      text[],
    ip_allowlist              cidr[],
    enforce_sso               boolean     NOT NULL DEFAULT false,
    break_glass_principal_id  uuid,
    created_by                uuid,
    created_at                timestamptz NOT NULL DEFAULT now(),
    deleted_at                timestamptz,
    purge_after               timestamptz,
    UNIQUE (tenant_id, resource_id),
    UNIQUE (tenant_id, slug),
    FOREIGN KEY (tenant_id, resource_id) REFERENCES aos.resources (tenant_id, id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------
-- 4. Permissions and roles
-- ---------------------------------------------------------------------

-- A dotted action name the application's code checks. Created with the
-- SDK ('code') or in the tenant admin portal ('portal') (PERM-2).
CREATE TABLE aos.permissions (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    name               text        NOT NULL
                       CHECK (name ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'),
    description        text,
    source             text        NOT NULL CHECK (source IN ('system', 'code', 'portal')),
    -- A second factor no older than this is needed (SIGN-9). Null means none.
    step_up_seconds    integer,
    -- An agent must wait for a human to approve (MACH-9).
    needs_approval     boolean     NOT NULL DEFAULT false,
    -- When a check last asked about it. Null marks "never checked".
    last_checked_at    timestamptz,
    retired_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

-- A named bundle of permissions. Owner is the only one AOS ships.
-- organization_id is set for a role that exists in one organization only.
CREATE TABLE aos.roles (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    name             text        NOT NULL,
    description      text,
    source           text        NOT NULL CHECK (source IN ('system', 'code', 'portal', 'organization')),
    organization_id  uuid,
    created_by       uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, organization_id)
        REFERENCES aos.organizations (tenant_id, resource_id) ON DELETE CASCADE,
    CHECK ((source = 'organization') = (organization_id IS NOT NULL))
);
CREATE UNIQUE INDEX roles_name_tenant ON aos.roles (tenant_id, name) WHERE organization_id IS NULL;
CREATE UNIQUE INDEX roles_name_org ON aos.roles (tenant_id, organization_id, name)
    WHERE organization_id IS NOT NULL;

-- What a role holds: an exact permission name, a prefix such as
-- 'payment.*', or '*'. Stored as patterns so wildcards need no expansion.
CREATE TABLE aos.role_permissions (
    tenant_id  uuid NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    role_id    uuid NOT NULL,
    pattern    text NOT NULL
               CHECK (pattern = '*' OR pattern ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*(\.\*)?$'),
    PRIMARY KEY (role_id, pattern),
    FOREIGN KEY (tenant_id, role_id) REFERENCES aos.roles (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE aos.tenants
    ADD CONSTRAINT tenants_default_role_fk
        FOREIGN KEY (id, default_role_id) REFERENCES aos.roles (tenant_id, id),
    ADD CONSTRAINT tenants_root_resource_fk
        FOREIGN KEY (id, root_resource_id) REFERENCES aos.resources (tenant_id, id);

-- The one matcher used by every permission query (PERM-8).
CREATE FUNCTION aos.permission_matches(pattern text, permission text)
RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT pattern = '*'
        OR pattern = permission
        OR (right(pattern, 2) = '.*'
            AND starts_with(permission, left(pattern, length(pattern) - 1)));
$$;

-- ---------------------------------------------------------------------
-- 5. Enterprise connections (defined here because groups refer to them)
-- ---------------------------------------------------------------------

-- One organization's link to its company identity provider (ENT-1, ENT-3).
CREATE TABLE aos.sso_connections (
    id                           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                    uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    organization_id              uuid        NOT NULL,
    protocol                     text        NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    status                       text        NOT NULL DEFAULT 'draft'
                                 CHECK (status IN ('draft', 'active', 'disabled')),
    oidc_issuer                  text,
    oidc_client_id               text,
    oidc_client_secret_encrypted bytea,
    saml_idp_entity_id           text,
    saml_idp_sso_url             text,
    saml_idp_certificate         text,
    data_key_id                  uuid,
    -- Accept the company's own second factor, or ask for an AOS one too.
    trust_idp_second_factor      boolean     NOT NULL DEFAULT true,
    default_role_id              uuid,
    created_at                   timestamptz NOT NULL DEFAULT now(),
    activated_at                 timestamptz,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, organization_id)
        REFERENCES aos.organizations (tenant_id, resource_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, default_role_id) REFERENCES aos.roles (tenant_id, id),
    FOREIGN KEY (tenant_id, data_key_id) REFERENCES aos.data_keys (tenant_id, id)
);
CREATE INDEX sso_connections_org ON aos.sso_connections (tenant_id, organization_id);

-- A company email domain, proven by a DNS record (ENT-2).
CREATE TABLE aos.verified_domains (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    organization_id  uuid        NOT NULL,
    domain           citext      NOT NULL,
    txt_value        text        NOT NULL,
    verified_at      timestamptz,
    last_checked_at  timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, organization_id)
        REFERENCES aos.organizations (tenant_id, resource_id) ON DELETE CASCADE
);
-- One organization per verified domain in a tenant.
CREATE UNIQUE INDEX verified_domains_one_owner
    ON aos.verified_domains (tenant_id, domain) WHERE verified_at IS NOT NULL;

-- One organization's directory-sync endpoint (ENT-5).
CREATE TABLE aos.scim_directories (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    organization_id  uuid        NOT NULL,
    token_hash       bytea       NOT NULL UNIQUE,
    default_role_id  uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_request_at  timestamptz,
    disabled_at      timestamptz,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, organization_id)
        REFERENCES aos.organizations (tenant_id, resource_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, default_role_id) REFERENCES aos.roles (tenant_id, id)
);

-- ---------------------------------------------------------------------
-- 6. Groups and grants
-- ---------------------------------------------------------------------

CREATE TABLE aos.groups (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    organization_id  uuid,
    name             text        NOT NULL,
    -- Set when the group is synced from a company directory.
    directory_id     uuid,
    external_id      text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, organization_id)
        REFERENCES aos.organizations (tenant_id, resource_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, directory_id) REFERENCES aos.scim_directories (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX groups_directory_external
    ON aos.groups (directory_id, external_id) WHERE directory_id IS NOT NULL;
CREATE INDEX groups_org ON aos.groups (tenant_id, organization_id);

CREATE TABLE aos.group_members (
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    group_id      uuid        NOT NULL,
    principal_id  uuid        NOT NULL,
    added_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, principal_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES aos.groups (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX group_members_principal ON aos.group_members (tenant_id, principal_id);

-- The heart of the model: a principal or a group, a role, a resource,
-- allow or deny, with an optional condition and expiry (PERM-1, PERM-4).
-- Holding a grant in an organization is what membership means.
CREATE TABLE aos.grants (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id  uuid,
    group_id      uuid,
    role_id       uuid        NOT NULL,
    resource_id   uuid        NOT NULL,
    effect        text        NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
    -- A CEL expression. Null means no condition (PERM-9).
    condition     text,
    expires_at    timestamptz,
    source        text        NOT NULL DEFAULT 'manual'
                  CHECK (source IN ('system', 'manual', 'invitation', 'default_role',
                                    'sso', 'directory', 'elevation', 'support')),
    reason        text,
    created_by    uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    -- Exactly one of principal and group.
    CHECK (num_nonnulls(principal_id, group_id) = 1),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, group_id) REFERENCES aos.groups (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, role_id) REFERENCES aos.roles (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_id) REFERENCES aos.resources (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX grants_principal ON aos.grants (tenant_id, principal_id, resource_id)
    WHERE principal_id IS NOT NULL;
CREATE INDEX grants_group ON aos.grants (tenant_id, group_id, resource_id)
    WHERE group_id IS NOT NULL;
CREATE INDEX grants_resource ON aos.grants (tenant_id, resource_id);
CREATE INDEX grants_role ON aos.grants (tenant_id, role_id);
CREATE INDEX grants_expiry ON aos.grants (expires_at) WHERE expires_at IS NOT NULL;

-- Which company group becomes which role, and where (ENT-1 step 9).
CREATE TABLE aos.sso_group_mappings (
    tenant_id       uuid NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    connection_id   uuid NOT NULL,
    external_group  text NOT NULL,
    role_id         uuid NOT NULL,
    resource_id     uuid NOT NULL,
    PRIMARY KEY (connection_id, external_group, role_id, resource_id),
    FOREIGN KEY (tenant_id, connection_id) REFERENCES aos.sso_connections (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, role_id) REFERENCES aos.roles (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_id) REFERENCES aos.resources (tenant_id, id) ON DELETE CASCADE
);

-- Bound to one email address. Accepting writes a grant and nothing else:
-- an invitation can never touch an existing account's credentials (ORG-2).
CREATE TABLE aos.invitations (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    email                 citext      NOT NULL,
    role_id               uuid        NOT NULL,
    resource_id           uuid        NOT NULL,
    inviter_principal_id  uuid,
    token_hash            bytea       NOT NULL UNIQUE,
    expires_at            timestamptz NOT NULL,
    accepted_at           timestamptz,
    accepted_by           uuid,
    declined_at           timestamptz,
    revoked_at            timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, role_id) REFERENCES aos.roles (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_id) REFERENCES aos.resources (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX invitations_email ON aos.invitations (tenant_id, email);
CREATE INDEX invitations_resource ON aos.invitations (tenant_id, resource_id);

-- A request for a role for a limited time (PERM-9, WHO-11).
CREATE TABLE aos.elevation_requests (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id      uuid        NOT NULL,
    role_id           uuid        NOT NULL,
    resource_id       uuid        NOT NULL,
    reason            text        NOT NULL,
    duration_seconds  integer     NOT NULL CHECK (duration_seconds > 0),
    status            text        NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    decided_by        uuid,
    decided_at        timestamptz,
    grant_id          uuid,
    created_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, role_id) REFERENCES aos.roles (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_id) REFERENCES aos.resources (tenant_id, id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------
-- 7. Proving who you are
-- ---------------------------------------------------------------------

-- Single-use tokens sent by email or SMS. Only the hash is stored. The
-- raw value exists only in the message that carried it.
CREATE TABLE aos.tokens (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    purpose       text        NOT NULL
                  CHECK (purpose IN ('email_verification', 'password_reset', 'magic_link',
                                     'one_time_code', 'owner_setup', 'email_change',
                                     'export_download', 'sso_setup', 'account_unlock')),
    principal_id  uuid,
    -- The email address or phone number it was sent to.
    target        text,
    token_hash    bytea       NOT NULL,
    attempts      smallint    NOT NULL DEFAULT 0,
    max_attempts  smallint    NOT NULL DEFAULT 1,
    payload       jsonb       NOT NULL DEFAULT '{}',
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX tokens_hash ON aos.tokens (tenant_id, token_hash);
CREATE INDEX tokens_principal ON aos.tokens (tenant_id, principal_id, purpose);
CREATE INDEX tokens_expiry ON aos.tokens (expires_at);

-- Password hashes. A sign-up that is not yet verified stores its password
-- as 'pending', tied to its own verification token (REG-3).
CREATE TABLE aos.passwords (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id  uuid        NOT NULL,
    -- A PHC string: algorithm, parameters, salt and hash together.
    hash          text        NOT NULL,
    status        text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending')),
    token_id      uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, token_id) REFERENCES aos.tokens (tenant_id, id) ON DELETE CASCADE,
    CHECK ((status = 'pending') = (token_id IS NOT NULL))
);
CREATE UNIQUE INDEX passwords_one_active ON aos.passwords (principal_id) WHERE status = 'active';

CREATE TABLE aos.passkeys (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id     uuid        NOT NULL,
    credential_id    bytea       NOT NULL,
    public_key       bytea       NOT NULL,
    -- Must never go backwards. A lower value suggests a copied key.
    sign_count       bigint      NOT NULL DEFAULT 0,
    transports       text[]      NOT NULL DEFAULT '{}',
    aaguid           uuid,
    backup_eligible  boolean     NOT NULL DEFAULT false,
    backed_up        boolean     NOT NULL DEFAULT false,
    name             text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_used_at     timestamptz,
    UNIQUE (tenant_id, credential_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX passkeys_principal ON aos.passkeys (tenant_id, principal_id);

-- Authenticator-app seeds, encrypted.
CREATE TABLE aos.totp_factors (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id      uuid        NOT NULL,
    secret_encrypted  bytea       NOT NULL,
    data_key_id       uuid        NOT NULL,
    confirmed_at      timestamptz,
    -- The last time step accepted, so a code cannot be replayed.
    last_used_step    bigint,
    created_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, data_key_id) REFERENCES aos.data_keys (tenant_id, id)
);
CREATE INDEX totp_factors_principal ON aos.totp_factors (tenant_id, principal_id);

CREATE TABLE aos.recovery_codes (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id  uuid        NOT NULL,
    code_hash     bytea       NOT NULL,
    used_at       timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX recovery_codes_principal ON aos.recovery_codes (tenant_id, principal_id);

-- Social sign-in settings for the tenant (Google, GitHub and so on).
CREATE TABLE aos.oauth_providers (
    id                       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    provider                 text        NOT NULL,
    client_id                text        NOT NULL,
    client_secret_encrypted  bytea       NOT NULL,
    data_key_id              uuid        NOT NULL,
    scopes                   text[]      NOT NULL DEFAULT '{}',
    enabled                  boolean     NOT NULL DEFAULT true,
    created_at               timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider),
    FOREIGN KEY (tenant_id, data_key_id) REFERENCES aos.data_keys (tenant_id, id)
);

-- A link between a principal and an account elsewhere: a social account,
-- a company identity-provider account, or a directory entry.
CREATE TABLE aos.external_identities (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id     uuid        NOT NULL,
    provider         text        NOT NULL,
    connection_id    uuid,
    directory_id     uuid,
    -- The other system's own id for this person.
    subject          text        NOT NULL,
    email            citext,
    email_verified   boolean     NOT NULL DEFAULT false,
    profile          jsonb       NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_sign_in_at  timestamptz,
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, connection_id) REFERENCES aos.sso_connections (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, directory_id) REFERENCES aos.scim_directories (tenant_id, id) ON DELETE CASCADE,
    CHECK (num_nonnulls(connection_id, directory_id) <= 1)
);
CREATE UNIQUE INDEX external_identities_social
    ON aos.external_identities (tenant_id, provider, subject)
    WHERE connection_id IS NULL AND directory_id IS NULL;
CREATE UNIQUE INDEX external_identities_sso
    ON aos.external_identities (connection_id, subject) WHERE connection_id IS NOT NULL;
CREATE UNIQUE INDEX external_identities_directory
    ON aos.external_identities (directory_id, subject) WHERE directory_id IS NOT NULL;
CREATE INDEX external_identities_principal ON aos.external_identities (tenant_id, principal_id);

-- Short-lived state for steps in progress: a passkey challenge, a sign-in
-- waiting for its second factor, a redirect to a provider.
CREATE TABLE aos.challenges (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    kind          text        NOT NULL
                  CHECK (kind IN ('passkey_registration', 'passkey_sign_in', 'pending_sign_in',
                                  'oauth_state', 'saml_request')),
    principal_id  uuid,
    data          jsonb       NOT NULL DEFAULT '{}',
    attempts      smallint    NOT NULL DEFAULT 0,
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX challenges_expiry ON aos.challenges (expires_at);

-- Values that must be accepted once only, such as a SAML assertion id.
CREATE TABLE aos.seen_nonces (
    tenant_id   uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    kind        text        NOT NULL,
    value_hash  bytea       NOT NULL,
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, kind, value_hash)
);
CREATE INDEX seen_nonces_expiry ON aos.seen_nonces (expires_at);

-- Counters for rate limits and lockout (SIGN-10). Updated with one atomic
-- "insert, or add one" statement, so parallel requests cannot slip past.
CREATE TABLE aos.rate_limits (
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    bucket        text        NOT NULL,
    key_hash      bytea       NOT NULL,
    window_start  timestamptz NOT NULL DEFAULT now(),
    count         integer     NOT NULL DEFAULT 0,
    locked_until  timestamptz,
    PRIMARY KEY (tenant_id, bucket, key_hash)
);

-- ---------------------------------------------------------------------
-- 8. Sessions and tokens
-- ---------------------------------------------------------------------

-- Devices a principal has signed in from, for the new-device alert.
CREATE TABLE aos.devices (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id   uuid        NOT NULL,
    device_hash    bytea       NOT NULL,
    label          text,
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (principal_id, device_hash),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE
);

-- A signed-in state. The browser holds a random id. Only its hash is here.
CREATE TABLE aos.sessions (
    id                         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                  uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id               uuid        NOT NULL,
    id_hash                    bytea       NOT NULL UNIQUE,
    kind                       text        NOT NULL DEFAULT 'browser' CHECK (kind IN ('browser', 'token')),
    -- The organization the user is working in. A convenience for screens,
    -- never a security boundary: every check looks at the resource itself.
    active_resource_id         uuid,
    assurance_level            smallint    NOT NULL DEFAULT 0,
    -- Each method used and when: [{"method": "password", "at": "..."}].
    auth_methods               jsonb       NOT NULL DEFAULT '[]',
    second_factor_at           timestamptz,
    -- Set when a support person is acting as this user (ADM-3).
    impersonator_principal_id  uuid,
    impersonation_reason       text,
    device_id                  uuid,
    user_agent                 text,
    ip                         inet,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    last_seen_at               timestamptz NOT NULL DEFAULT now(),
    idle_expires_at            timestamptz NOT NULL,
    absolute_expires_at        timestamptz NOT NULL,
    revoked_at                 timestamptz,
    revoked_reason             text,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, device_id) REFERENCES aos.devices (tenant_id, id),
    CHECK ((impersonator_principal_id IS NULL) = (impersonation_reason IS NULL))
);
CREATE INDEX sessions_principal ON aos.sessions (tenant_id, principal_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expiry ON aos.sessions (absolute_expires_at);

-- Another application registered to use this tenant for sign-in, or a
-- machine client (MACH-5, MACH-6, MACH-7).
CREATE TABLE aos.oauth_clients (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    client_id             text        NOT NULL,
    name                  text        NOT NULL,
    kind                  text        NOT NULL
                          CHECK (kind IN ('confidential', 'public', 'metadata_document')),
    secret_hash           bytea,
    metadata_url          text,
    redirect_uris         text[]      NOT NULL DEFAULT '{}',
    allowed_scopes        text[]      NOT NULL DEFAULT '{}',
    grant_types           text[]      NOT NULL DEFAULT '{authorization_code}',
    -- For client credentials: the service account the client acts as.
    service_principal_id  uuid,
    created_at            timestamptz NOT NULL DEFAULT now(),
    disabled_at           timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, client_id),
    FOREIGN KEY (tenant_id, service_principal_id) REFERENCES aos.principals (tenant_id, id)
);

-- All refresh tokens from one sign-in form a family. Reuse of an old one
-- ends the whole family (SIGN-8).
CREATE TABLE aos.token_families (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id    uuid        NOT NULL,
    session_id      uuid,
    client_id       uuid,
    scopes          text[]      NOT NULL DEFAULT '{}',
    audience        text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    revoked_reason  text,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, session_id) REFERENCES aos.sessions (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, client_id) REFERENCES aos.oauth_clients (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX token_families_principal ON aos.token_families (tenant_id, principal_id);

CREATE TABLE aos.refresh_tokens (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    family_id   uuid        NOT NULL,
    token_hash  bytea       NOT NULL UNIQUE,
    expires_at  timestamptz NOT NULL,
    -- A token that arrives again after this is set means someone has a copy.
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, family_id) REFERENCES aos.token_families (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX refresh_tokens_family ON aos.refresh_tokens (tenant_id, family_id);

-- ---------------------------------------------------------------------
-- 9. Machines, other applications and agents
-- ---------------------------------------------------------------------

-- A key belongs to a principal. Its scopes can only narrow what that
-- principal may do (MACH-2).
CREATE TABLE aos.api_keys (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id  uuid        NOT NULL,
    name          text        NOT NULL,
    public_id     text        NOT NULL UNIQUE,
    secret_hash   bytea       NOT NULL,
    scopes        text[]      NOT NULL DEFAULT '{*}',
    expires_at    timestamptz,
    revoked_at    timestamptz,
    last_used_at  timestamptz,
    created_by    uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX api_keys_principal ON aos.api_keys (tenant_id, principal_id);

CREATE TABLE aos.oauth_authorization_codes (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    code_hash       bytea       NOT NULL UNIQUE,
    client_id       uuid        NOT NULL,
    principal_id    uuid        NOT NULL,
    redirect_uri    text        NOT NULL,
    scopes          text[]      NOT NULL DEFAULT '{}',
    code_challenge  text        NOT NULL,
    -- The one service the token is for (MACH-7).
    resource        text,
    nonce           text,
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, client_id) REFERENCES aos.oauth_clients (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE aos.oauth_consents (
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    principal_id  uuid        NOT NULL,
    client_id     uuid        NOT NULL,
    scopes        text[]      NOT NULL DEFAULT '{}',
    granted_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz,
    PRIMARY KEY (principal_id, client_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, client_id) REFERENCES aos.oauth_clients (tenant_id, id) ON DELETE CASCADE
);

-- Sign-in for devices with no browser, such as the CLI (MACH-6).
CREATE TABLE aos.device_codes (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    client_id         uuid        NOT NULL,
    device_code_hash  bytea       NOT NULL UNIQUE,
    user_code         text        NOT NULL,
    principal_id      uuid,
    scopes            text[]      NOT NULL DEFAULT '{}',
    status            text        NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'used')),
    expires_at        timestamptz NOT NULL,
    last_polled_at    timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_code),
    FOREIGN KEY (tenant_id, client_id) REFERENCES aos.oauth_clients (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE
);

-- What a user let an agent do for them, where, and until when (MACH-8).
CREATE TABLE aos.delegations (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    agent_principal_id  uuid        NOT NULL,
    user_principal_id   uuid        NOT NULL,
    scopes              text[]      NOT NULL,
    resource_id         uuid        NOT NULL,
    expires_at          timestamptz NOT NULL,
    revoked_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, agent_principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_id) REFERENCES aos.resources (tenant_id, id) ON DELETE CASCADE,
    CHECK (agent_principal_id <> user_principal_id)
);
CREATE INDEX delegations_agent ON aos.delegations (tenant_id, agent_principal_id);

-- An agent's request that waits for a human (MACH-9). The digest binds
-- the approval to one exact action and its values.
CREATE TABLE aos.approvals (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    agent_principal_id  uuid        NOT NULL,
    user_principal_id   uuid        NOT NULL,
    permission          text        NOT NULL,
    resource_id         uuid        NOT NULL,
    action_digest       bytea       NOT NULL,
    details             jsonb       NOT NULL DEFAULT '{}',
    status              text        NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved', 'declined', 'expired', 'used')),
    expires_at          timestamptz NOT NULL,
    decided_at          timestamptz,
    used_at             timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, agent_principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_principal_id) REFERENCES aos.principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_id) REFERENCES aos.resources (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX approvals_user ON aos.approvals (tenant_id, user_principal_id, status);

-- ---------------------------------------------------------------------
-- 10. Audit log, decisions, events and messages
-- ---------------------------------------------------------------------

-- One row per tenant, locked while an audit entry is appended, so the
-- chain has exactly one order.
CREATE TABLE aos.audit_heads (
    tenant_id  uuid   PRIMARY KEY REFERENCES aos.tenants (id) ON DELETE CASCADE,
    last_seq   bigint NOT NULL DEFAULT 0,
    last_hash  bytea
);

-- Append-only. Each entry carries the hash of the one before it, so a
-- changed or removed entry breaks the chain (ADM-4). It holds ids, never
-- names or addresses, so erasing a person does not touch it.
CREATE TABLE aos.audit_log (
    tenant_id                  uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    seq                        bigint      NOT NULL,
    occurred_at                timestamptz NOT NULL DEFAULT now(),
    organization_id            uuid,
    actor_principal_id         uuid,
    impersonator_principal_id  uuid,
    on_behalf_of_principal_id  uuid,
    action                     text        NOT NULL,
    target_type                text,
    target_id                  text,
    result                     text        NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    reason_code                text,
    session_id                 uuid,
    request_id                 text,
    data                       jsonb       NOT NULL DEFAULT '{}',
    prev_hash                  bytea,
    hash                       bytea       NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);
CREATE INDEX audit_log_time ON aos.audit_log (tenant_id, occurred_at);
CREATE INDEX audit_log_actor ON aos.audit_log (tenant_id, actor_principal_id, occurred_at);
CREATE INDEX audit_log_org ON aos.audit_log (tenant_id, organization_id, occurred_at);
CREATE INDEX audit_log_action ON aos.audit_log (tenant_id, action, occurred_at);

-- Personal details of an audit entry, kept apart and outside the hash,
-- so they can be erased without breaking the chain.
CREATE TABLE aos.audit_log_personal (
    tenant_id   uuid   NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    seq         bigint NOT NULL,
    ip          inet,
    user_agent  text,
    PRIMARY KEY (tenant_id, seq),
    FOREIGN KEY (tenant_id, seq) REFERENCES aos.audit_log (tenant_id, seq) ON DELETE CASCADE
);

CREATE FUNCTION aos.audit_log_is_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'aos.audit_log is append-only: entries cannot be changed';
END;
$$;
CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON aos.audit_log
    FOR EACH ROW EXECUTE FUNCTION aos.audit_log_is_append_only();

-- Permission decisions: every deny, every use of an admin permission,
-- and a sample of allows (PERM-12). High volume, so apart from the audit log.
CREATE TABLE aos.decision_log (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id     uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    decided_at    timestamptz NOT NULL DEFAULT now(),
    principal_id  uuid,
    permission    text        NOT NULL,
    resource_id   uuid,
    decision      text        NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason_code   text,
    via           text        NOT NULL DEFAULT 'session'
                  CHECK (via IN ('session', 'api_key', 'service', 'agent', 'support')),
    api_key_id    uuid,
    grant_id      uuid,
    request_id    text
);
CREATE INDEX decision_log_time ON aos.decision_log (tenant_id, decided_at);
CREATE INDEX decision_log_principal ON aos.decision_log (tenant_id, principal_id, decided_at);

-- The outbox. A change writes its event here in the same transaction,
-- and a worker delivers it afterwards (ADM-5).
CREATE TABLE aos.events (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    seq              bigint      GENERATED ALWAYS AS IDENTITY,
    type             text        NOT NULL,
    organization_id  uuid,
    payload          jsonb       NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    dispatched_at    timestamptz,
    UNIQUE (tenant_id, id)
);
CREATE INDEX events_undispatched ON aos.events (seq) WHERE dispatched_at IS NULL;

-- Where events go. Also holds the HTTP callbacks used as before-hooks and
-- the per-organization audit export (SYS-6, ENT-8).
CREATE TABLE aos.webhook_endpoints (
    id                        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                 uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    organization_id           uuid,
    kind                      text        NOT NULL DEFAULT 'events'
                              CHECK (kind IN ('events', 'before_hook', 'audit_export')),
    url                       text        NOT NULL,
    signing_secret_encrypted  bytea       NOT NULL,
    data_key_id               uuid        NOT NULL,
    event_types               text[]      NOT NULL DEFAULT '{*}',
    timeout_ms                integer     NOT NULL DEFAULT 2000,
    enabled                   boolean     NOT NULL DEFAULT true,
    created_at                timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, organization_id)
        REFERENCES aos.organizations (tenant_id, resource_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, data_key_id) REFERENCES aos.data_keys (tenant_id, id)
);

CREATE TABLE aos.webhook_deliveries (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    endpoint_id       uuid        NOT NULL,
    event_id          uuid        NOT NULL,
    status            text        NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'delivered', 'failed')),
    attempts          integer     NOT NULL DEFAULT 0,
    next_attempt_at   timestamptz,
    last_status_code  integer,
    last_error        text,
    delivered_at      timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (endpoint_id, event_id),
    FOREIGN KEY (tenant_id, endpoint_id) REFERENCES aos.webhook_endpoints (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, event_id) REFERENCES aos.events (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX webhook_deliveries_due ON aos.webhook_deliveries (next_attempt_at) WHERE status = 'pending';

-- Emails and SMS waiting to be sent. The body can hold a raw token, so it
-- is encrypted and wiped as soon as the message has been sent.
CREATE TABLE aos.messages (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    channel          text        NOT NULL CHECK (channel IN ('email', 'sms', 'whatsapp')),
    recipient        text        NOT NULL,
    template         text        NOT NULL,
    locale           text,
    body_encrypted   bytea,
    data_key_id      uuid,
    status           text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts         integer     NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz,
    sent_at          timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, data_key_id) REFERENCES aos.data_keys (tenant_id, id),
    CHECK (status <> 'sent' OR body_encrypted IS NULL)
);
CREATE INDEX messages_due ON aos.messages (next_attempt_at) WHERE status = 'pending';

-- ---------------------------------------------------------------------
-- 11. Access reviews (M7)
-- ---------------------------------------------------------------------

CREATE TABLE aos.access_reviews (
    id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    organization_id        uuid,
    status                 text        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'completed')),
    reviewer_principal_id  uuid,
    due_at                 timestamptz,
    completed_at           timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, organization_id)
        REFERENCES aos.organizations (tenant_id, resource_id) ON DELETE CASCADE
);

CREATE TABLE aos.access_review_items (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES aos.tenants (id) ON DELETE CASCADE,
    review_id   uuid        NOT NULL,
    -- Plain id: the grant may be removed by the review itself.
    grant_id    uuid        NOT NULL,
    decision    text        CHECK (decision IN ('keep', 'remove')),
    decided_at  timestamptz,
    FOREIGN KEY (tenant_id, review_id) REFERENCES aos.access_reviews (tenant_id, id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------
-- 12. Keeping the resource tree consistent
-- ---------------------------------------------------------------------

-- A new node gets a row for itself and one for each ancestor of its parent.
CREATE FUNCTION aos.resources_after_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO aos.resource_ancestors (tenant_id, resource_id, ancestor_id, depth)
    VALUES (NEW.tenant_id, NEW.id, NEW.id, 0);

    IF NEW.parent_id IS NOT NULL THEN
        INSERT INTO aos.resource_ancestors (tenant_id, resource_id, ancestor_id, depth)
        SELECT NEW.tenant_id, NEW.id, a.ancestor_id, a.depth + 1
        FROM aos.resource_ancestors a
        WHERE a.tenant_id = NEW.tenant_id
          AND a.resource_id = NEW.parent_id;
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER resources_closure
    AFTER INSERT ON aos.resources
    FOR EACH ROW EXECUTE FUNCTION aos.resources_after_insert();

-- Moving a node changes which grants it inherits (PERM-3). This is the
-- only supported way to change parent_id.
CREATE FUNCTION aos.move_resource(p_resource uuid, p_new_parent uuid) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM aos.resource_ancestors
               WHERE resource_id = p_new_parent AND ancestor_id = p_resource) THEN
        RAISE EXCEPTION 'a resource cannot be moved under itself';
    END IF;

    -- Cut every link from the moved subtree to the old ancestors.
    DELETE FROM aos.resource_ancestors link
    USING aos.resource_ancestors sub, aos.resource_ancestors old
    WHERE sub.ancestor_id = p_resource
      AND old.resource_id = p_resource AND old.depth > 0
      AND link.resource_id = sub.resource_id
      AND link.ancestor_id = old.ancestor_id;

    UPDATE aos.resources SET parent_id = p_new_parent WHERE id = p_resource;

    -- Link the moved subtree to the new ancestors.
    INSERT INTO aos.resource_ancestors (tenant_id, resource_id, ancestor_id, depth)
    SELECT sub.tenant_id, sub.resource_id, up.ancestor_id, sub.depth + up.depth + 1
    FROM aos.resource_ancestors sub, aos.resource_ancestors up
    WHERE sub.ancestor_id = p_resource
      AND up.resource_id = p_new_parent;
END;
$$;

-- ---------------------------------------------------------------------
-- 13. Tenant isolation: row-level security
-- ---------------------------------------------------------------------

-- The engine sets the tenant at the start of every transaction:
--     SET LOCAL aos.tenant_id = '<tenant uuid>';
-- With nothing set, every query below returns no rows.
CREATE FUNCTION aos.current_tenant() RETURNS uuid
LANGUAGE sql STABLE
AS $$
    SELECT nullif(current_setting('aos.tenant_id', true), '')::uuid;
$$;

-- The role the engine connects as. It does not own the tables, so the
-- policies apply to it. The table owner is used only for migrations.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aos_app') THEN
        CREATE ROLE aos_app NOLOGIN;
    END IF;
END;
$$;

DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables tb
          ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
        WHERE c.table_schema = 'aos'
          AND c.column_name = 'tenant_id'
          AND tb.table_type = 'BASE TABLE'
    LOOP
        EXECUTE format('ALTER TABLE aos.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON aos.%I
                 USING (tenant_id = aos.current_tenant())
                 WITH CHECK (tenant_id = aos.current_tenant())', t);
    END LOOP;
END;
$$;

ALTER TABLE aos.tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON aos.tenants
    USING (id = aos.current_tenant())
    WITH CHECK (id = aos.current_tenant());

GRANT USAGE ON SCHEMA aos TO aos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA aos TO aos_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA aos TO aos_app;
-- The engine can add audit entries and read them. It cannot change or remove them.
REVOKE UPDATE, DELETE ON aos.audit_log FROM aos_app;
REVOKE INSERT, UPDATE, DELETE ON aos.schema_migrations FROM aos_app;

-- ---------------------------------------------------------------------
-- 14. Finding the tenant before it is known
-- ---------------------------------------------------------------------

-- A request arrives with a key or at a hostname, and the tenant is not
-- known yet. These functions answer exactly that one question and nothing
-- more, so the engine never needs to read across tenants.

CREATE FUNCTION aos.resolve_tenant_key(p_public_id text)
RETURNS TABLE (tenant_id uuid, key_id uuid, kind text, secret_hash bytea, tenant_status text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = aos, pg_temp
AS $$
    SELECT k.tenant_id, k.id, k.kind, k.secret_hash, t.status
    FROM aos.tenant_keys k
    JOIN aos.tenants t ON t.id = k.tenant_id
    WHERE k.public_id = p_public_id
      AND k.revoked_at IS NULL
      AND (k.expires_at IS NULL OR k.expires_at > now());
$$;

CREATE FUNCTION aos.resolve_tenant_hostname(p_hostname text)
RETURNS TABLE (tenant_id uuid, purpose text, tenant_status text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = aos, pg_temp
AS $$
    SELECT h.tenant_id, h.purpose, t.status
    FROM aos.tenant_hostnames h
    JOIN aos.tenants t ON t.id = h.tenant_id
    WHERE h.hostname = lower(p_hostname)
      AND h.verified_at IS NOT NULL;
$$;

CREATE FUNCTION aos.resolve_scim_token(p_token_hash bytea)
RETURNS TABLE (tenant_id uuid, directory_id uuid, organization_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = aos, pg_temp
AS $$
    SELECT d.tenant_id, d.id, d.organization_id
    FROM aos.scim_directories d
    WHERE d.token_hash = p_token_hash
      AND d.disabled_at IS NULL;
$$;

REVOKE ALL ON FUNCTION aos.resolve_tenant_key(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION aos.resolve_tenant_hostname(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION aos.resolve_scim_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aos.resolve_tenant_key(text) TO aos_app;
GRANT EXECUTE ON FUNCTION aos.resolve_tenant_hostname(text) TO aos_app;
GRANT EXECUTE ON FUNCTION aos.resolve_scim_token(bytea) TO aos_app;
