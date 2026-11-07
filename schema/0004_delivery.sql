-- =====================================================================
-- 0004: webhook delivery, and what admin-created accounts need.
-- =====================================================================

-- The delivery worker must find due webhook deliveries across tenants.
-- As with messages, it gets ids only and opens each one in its tenant.
CREATE FUNCTION aos.due_deliveries(p_limit integer)
RETURNS TABLE (tenant_id uuid, delivery_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = aos, pg_temp
AS $$
    SELECT d.tenant_id, d.id
    FROM aos.webhook_deliveries d
    WHERE d.status = 'pending'
      AND (d.next_attempt_at IS NULL OR d.next_attempt_at <= now())
    ORDER BY d.created_at
    LIMIT p_limit;
$$;
REVOKE ALL ON FUNCTION aos.due_deliveries(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aos.due_deliveries(integer) TO aos_app;

-- A worker that finds a tenant by its slug, for the command line.
CREATE FUNCTION aos.resolve_tenant_slug(p_slug text)
RETURNS TABLE (tenant_id uuid, tenant_status text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = aos, pg_temp
AS $$
    SELECT t.id, t.status FROM aos.tenants t WHERE t.slug = p_slug;
$$;
REVOKE ALL ON FUNCTION aos.resolve_tenant_slug(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aos.resolve_tenant_slug(text) TO aos_app;

-- Webhook endpoints keep a short label and the time of the last success,
-- so an admin can tell a healthy endpoint from a dead one.
ALTER TABLE aos.webhook_endpoints
    ADD COLUMN label text,
    ADD COLUMN last_success_at timestamptz,
    ADD COLUMN last_failure_at timestamptz,
    ADD COLUMN last_error text;
