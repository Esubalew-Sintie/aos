-- =====================================================================
-- The platform role: the one database role that manages tenants as
-- accounts (create, rename, suspend) without reading inside any of them.
-- The engine switches to it when it creates a tenant.
--
-- The hosted service's own tables (applications, production requests,
-- limits, usage, support access) are not here; the hosted service adds
-- them in its own migrations.
-- =====================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aos_platform') THEN
        CREATE ROLE aos_platform NOLOGIN;
    END IF;
END;
$$;

-- It can see and manage every tenant as an account: name, status, settings.
GRANT USAGE ON SCHEMA aos TO aos_platform;
GRANT SELECT, INSERT, UPDATE ON aos.tenants TO aos_platform;
CREATE POLICY platform_manages_tenants ON aos.tenants
    TO aos_platform
    USING (true)
    WITH CHECK (true);

-- It has no rights on any other table in the aos schema. "Managing a
-- tenant is not reading it" is therefore enforced by the database: this
-- role cannot select a tenant's users, sessions, grants or audit log.
