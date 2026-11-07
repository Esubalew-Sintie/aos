-- =====================================================================
-- 0003: what the running engine needs on top of the agreed schema.
-- =====================================================================

-- The engine switches to aos_app (or aos_platform) inside every
-- transaction, so row-level security applies even when the connection
-- belongs to the table owner. The connecting role must be allowed to
-- make that switch.
GRANT aos_app TO CURRENT_USER;
GRANT aos_platform TO CURRENT_USER;

-- The delivery worker must find due messages across tenants. This
-- function answers only "which messages are due", as ids. The worker
-- then opens each one inside its own tenant, like any other request.
CREATE FUNCTION aos.due_messages(p_limit integer)
RETURNS TABLE (tenant_id uuid, message_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = aos, pg_temp
AS $$
    SELECT m.tenant_id, m.id
    FROM aos.messages m
    WHERE m.status = 'pending'
      AND (m.next_attempt_at IS NULL OR m.next_attempt_at <= now())
    ORDER BY m.created_at
    LIMIT p_limit;
$$;

REVOKE ALL ON FUNCTION aos.due_messages(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aos.due_messages(integer) TO aos_app;
