-- Enterprise sign-in and directory sync (slice 7).
ALTER TABLE aos.sso_connections ADD COLUMN name text;
ALTER TABLE aos.sso_connections ADD COLUMN last_test jsonb;
-- An audit export endpoint remembers how far it has sent.
ALTER TABLE aos.webhook_endpoints ADD COLUMN audit_cursor bigint NOT NULL DEFAULT 0;
-- The exporter finds every endpoint across tenants, as the delivery loop does.
CREATE FUNCTION aos.audit_export_endpoints()
RETURNS TABLE (tenant_id uuid, endpoint_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = aos, pg_temp
AS $$
    SELECT e.tenant_id, e.id FROM aos.webhook_endpoints e
    WHERE e.kind = 'audit_export' AND e.enabled;
$$;
REVOKE ALL ON FUNCTION aos.audit_export_endpoints() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aos.audit_export_endpoints() TO aos_app;
GRANT EXECUTE ON FUNCTION aos.resolve_scim_token(bytea) TO aos_app;
