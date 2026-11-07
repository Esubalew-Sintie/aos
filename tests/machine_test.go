package tests

import (
	"strings"
	"testing"
	"time"
)

type machineData struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
}

type keyData struct {
	ID       string   `json:"id"`
	PublicID string   `json:"public_id"`
	Scopes   []string `json:"scopes"`
	Key      string   `json:"key"`
}

type keyCheck struct {
	KeyID       string `json:"key_id"`
	PrincipalID string `json:"principal_id"`
	Kind        string `json:"kind"`
	Allowed     bool   `json:"allowed"`
	Reason      string `json:"reason"`
	ApprovalID  string `json:"approval_id"`
}

func TestServiceAccountsAndAPIKeys(t *testing.T) {
	w := newWorld(t)
	tn := w.tn

	// A service account is a principal with no password.
	r := tn.back("POST", "/v1/service-accounts", obj{"name": "Settlement job", "purpose": "nightly settlement", "owner_principal_id": w.hana})
	if r.Status != 201 {
		t.Fatalf("create service account: %d %s", r.Status, r.Raw)
	}
	var svc machineData
	r.data(&svc)
	if svc.Kind != "service" || svc.Status != "active" {
		t.Fatalf("service account: %+v", svc)
	}
	if r := tn.back("POST", "/v1/service-accounts", obj{"name": "x", "owner_principal_id": "00000000-0000-0000-0000-000000000000"}); r.Status != 400 {
		t.Fatalf("unknown owner: %d", r.Status)
	}
	w.grant(svc.ID, "Finance", "organization", "merchant-a", "allow")

	// A key with narrow scopes. Shown once, stored as a hash.
	r = tn.back("POST", "/v1/api-keys", obj{"principal_id": svc.ID, "name": "prod", "scopes": []string{"payment.read"}})
	if r.Status != 201 {
		t.Fatalf("create key: %d %s", r.Status, r.Raw)
	}
	var key keyData
	r.data(&key)
	if !strings.HasPrefix(key.Key, "aos_test_") || !strings.Contains(key.Key, ".") {
		t.Fatalf("key shape: %q", key.Key)
	}
	if n := tn.count(`SELECT count(*) FROM aos.api_keys WHERE secret_hash = $1`, []byte(strings.SplitN(key.Key, ".", 2)[1])); n != 0 {
		t.Fatal("the key secret is stored in clear")
	}
	var listed []keyData
	tn.back("GET", "/v1/api-keys?principal_id="+svc.ID, nil).data(&listed)
	if len(listed) != 1 || listed[0].Key != "" || listed[0].PublicID != key.PublicID {
		t.Fatalf("listed keys: %+v", listed)
	}

	// Checking: who is this, and may it do this? Scopes narrow.
	check := func(k, permission, resID string) keyCheck {
		t.Helper()
		body := obj{"key": k}
		if permission != "" {
			body["permission"] = permission
			body["resource"] = obj{"type": "branch", "id": resID}
		}
		r := tn.back("POST", "/v1/api-keys/check", body)
		if r.Status != 200 {
			t.Fatalf("check: %d %s", r.Status, r.Raw)
		}
		var out keyCheck
		r.data(&out)
		return out
	}
	who := check(key.Key, "", "")
	if who.PrincipalID != svc.ID || who.Kind != "service" {
		t.Fatalf("identify: %+v", who)
	}
	if c := check(key.Key, "payment.read", "branch-1"); !c.Allowed {
		t.Fatalf("within scope: %+v", c)
	}
	if c := check(key.Key, "payment.refund", "branch-1"); c.Allowed || c.Reason != "outside_scope" {
		t.Fatalf("outside scope: %+v", c)
	}
	// The principal's own rights still bound it: no grant at Merchant B.
	if c := check(key.Key, "payment.read", "branch-1"); !c.Allowed {
		t.Fatal("scoped key refused its own permission")
	}
	r = tn.back("POST", "/v1/api-keys/check", obj{"key": key.Key, "permission": "payment.read", "resource": obj{"type": "organization", "id": "merchant-b"}})
	var c keyCheck
	r.data(&c)
	if c.Allowed || c.Reason != "no_matching_grant" {
		t.Fatalf("beyond the principal's grants: %+v", c)
	}
	// Wrong secret, unknown key, revoked key: the same answer.
	for _, bad := range []string{key.PublicID + ".wrong", "aos_test_nope.secret", "garbage"} {
		if r := tn.back("POST", "/v1/api-keys/check", obj{"key": bad}); r.code() != "invalid_api_key" {
			t.Fatalf("bad key %q: %d %s", bad, r.Status, r.Raw)
		}
	}
	// A disabled service account's key stops; enabling brings it back.
	tn.back("POST", "/v1/machines/"+svc.ID+"/disable", obj{"reason": "maintenance"})
	if r := tn.back("POST", "/v1/api-keys/check", obj{"key": key.Key}); r.code() != "invalid_api_key" {
		t.Fatalf("key of a disabled account: %d %s", r.Status, r.Raw)
	}
	tn.back("POST", "/v1/machines/"+svc.ID+"/enable", nil)
	if c := check(key.Key, "", ""); c.PrincipalID != svc.ID {
		t.Fatal("key did not come back")
	}
	// Expiry and revocation.
	r = tn.back("POST", "/v1/api-keys", obj{"principal_id": svc.ID, "name": "short", "expires_at": time.Now().Add(time.Hour)})
	var short keyData
	r.data(&short)
	w.e.clock.advance(2 * time.Hour)
	if r := tn.back("POST", "/v1/api-keys/check", obj{"key": short.Key}); r.code() != "invalid_api_key" {
		t.Fatalf("expired key: %d %s", r.Status, r.Raw)
	}
	if r := tn.back("DELETE", "/v1/api-keys/"+key.ID, nil); r.Status != 200 {
		t.Fatalf("revoke: %d %s", r.Status, r.Raw)
	}
	if r := tn.back("POST", "/v1/api-keys/check", obj{"key": key.Key}); r.code() != "invalid_api_key" {
		t.Fatalf("revoked key: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.audit_log WHERE action IN ('apikey.created', 'apikey.revoked', 'service.created')`); n != 4 {
		t.Fatalf("audit entries: %d", n)
	}

	// A person issues keys for themselves only, at the frontend door.
	_, hana := tn.signInSession("hana@example.com", "some-password")
	r = tn.front("POST", "/v1/me/api-keys", obj{"name": "my script", "scopes": []string{"payment.*"}}, hana)
	if r.Status != 201 {
		t.Fatalf("own key: %d %s", r.Status, r.Raw)
	}
	var mine keyData
	r.data(&mine)
	if r := tn.front("POST", "/v1/me/api-keys", obj{"principal_id": w.sara, "name": "not mine"}, hana); r.Status != 403 {
		t.Fatalf("key for someone else: %d %s", r.Status, r.Raw)
	}
	if c := check(mine.Key, "payment.refund", "branch-2"); !c.Allowed || c.PrincipalID != w.hana {
		t.Fatalf("hana's key: %+v", c)
	}
	tn.front("GET", "/v1/me/api-keys", nil, hana).data(&listed)
	if len(listed) != 1 {
		t.Fatalf("hana's keys: %+v", listed)
	}
	if r := tn.front("DELETE", "/v1/me/api-keys/"+mine.ID, nil, hana); r.Status != 200 {
		t.Fatalf("revoke own key: %d %s", r.Status, r.Raw)
	}
}

func TestAgentsActForUsersWithinADelegation(t *testing.T) {
	w := newWorld(t)
	tn := w.tn
	w.ok(tn.back("PUT", "/v1/permissions", obj{"name": "payment.payout", "needs_approval": true}))
	w.ok(tn.back("PUT", "/v1/roles", obj{"name": "Finance", "permissions": []string{"payment.*"}}))

	r := tn.back("POST", "/v1/agents", obj{"name": "Refund helper", "purpose": "prepares refunds", "owner_principal_id": w.sara})
	if r.Status != 201 {
		t.Fatalf("create agent: %d %s", r.Status, r.Raw)
	}
	var agent machineData
	r.data(&agent)
	if r := tn.back("POST", "/v1/agents", obj{"name": "orphan"}); r.Status != 400 {
		t.Fatalf("agent without an owner: %d", r.Status)
	}
	ask := func(body obj) keyCheck {
		t.Helper()
		r := tn.back("POST", "/v1/can", body)
		if r.Status != 200 {
			t.Fatalf("can: %d %s", r.Status, r.Raw)
		}
		var out keyCheck
		r.data(&out)
		return out
	}
	// Without a delegation the agent has nothing, even though Sara does.
	if c := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.read", "resource": obj{"type": "branch", "id": "branch-1"}}); c.Allowed || c.Reason != "no_delegation" {
		t.Fatalf("no delegation: %+v", c)
	}
	// Sara delegates reading and refunds at Merchant A for eight hours.
	_, sara := tn.signInSession("sara@example.com", "some-password")
	r = tn.front("POST", "/v1/me/delegations", obj{"agent_id": agent.ID, "scopes": []string{"payment.read", "payment.refund"}, "resource": obj{"type": "organization", "id": "merchant-a"}, "hours": 8}, sara)
	if r.Status != 201 {
		t.Fatalf("delegate: %d %s", r.Status, r.Raw)
	}
	var delegation struct {
		ID string `json:"id"`
	}
	r.data(&delegation)
	if r := tn.front("POST", "/v1/me/delegations", obj{"agent_id": w.hana, "scopes": []string{"*"}, "resource": obj{"type": "organization", "id": "merchant-a"}, "hours": 1}, sara); r.Status != 400 {
		t.Fatalf("delegate to a person: %d %s", r.Status, r.Raw)
	}
	// All three must hold: the user has it, the delegation covers it, it has not expired.
	if c := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.read", "resource": obj{"type": "branch", "id": "branch-1"}}); !c.Allowed {
		t.Fatalf("delegated read: %+v", c)
	}
	if c := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.create", "resource": obj{"type": "branch", "id": "branch-1"}}); c.Allowed || c.Reason != "outside_delegation" {
		t.Fatalf("outside the delegation: %+v", c)
	}
	// Sara is denied refunds at branch 2, so her agent is too.
	if c := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.refund", "resource": obj{"type": "branch", "id": "branch-2"}}); c.Allowed || c.Reason != "denied_by_grant" {
		t.Fatalf("the user's own deny: %+v", c)
	}
	// Merchant B is outside the delegation's resource.
	if c := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.read", "resource": obj{"type": "organization", "id": "merchant-b"}}); c.Allowed || c.Reason != "no_delegation" {
		t.Fatalf("another resource: %+v", c)
	}
	var mine []struct {
		ID     string   `json:"id"`
		Scopes []string `json:"scopes"`
	}
	tn.front("GET", "/v1/me/delegations", nil, sara).data(&mine)
	if len(mine) != 1 || mine[0].ID != delegation.ID {
		t.Fatalf("delegations: %+v", mine)
	}

	// A sensitive action waits for a human (MACH-9).
	w.grant(w.sara, "Finance", "organization", "merchant-b", "allow")
	tn.front("POST", "/v1/me/delegations", obj{"agent_id": agent.ID, "scopes": []string{"payment.payout"}, "resource": obj{"type": "organization", "id": "merchant-b"}, "hours": 8}, sara)
	details := obj{"amount": 500, "to": "acct-9"}
	c := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.payout", "resource": obj{"type": "organization", "id": "merchant-b"}, "details": details})
	if c.Allowed || c.Reason != "approval_required" || c.ApprovalID == "" {
		t.Fatalf("payout: %+v", c)
	}
	w.e.deliver()
	if !w.e.mail.has("sara@example.com", "Refund helper asks your approval") {
		t.Fatal("sara was not asked")
	}
	// Asking again reuses the open request.
	if again := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.payout", "resource": obj{"type": "organization", "id": "merchant-b"}, "details": details}); again.ApprovalID != c.ApprovalID {
		t.Fatalf("a second request was made: %+v", again)
	}
	// Repeating with the id before a decision: still waiting.
	if p := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.payout", "resource": obj{"type": "organization", "id": "merchant-b"}, "details": details, "approval_id": c.ApprovalID}); p.Allowed || p.Reason != "approval_pending" {
		t.Fatalf("pending: %+v", p)
	}
	var pending []struct {
		ID        string         `json:"id"`
		AgentName string         `json:"agent_name"`
		Details   map[string]any `json:"details"`
	}
	tn.front("GET", "/v1/me/approvals", nil, sara).data(&pending)
	if len(pending) != 1 || pending[0].ID != c.ApprovalID || pending[0].AgentName != "Refund helper" || pending[0].Details["to"] != "acct-9" {
		t.Fatalf("sara's approvals: %+v", pending)
	}
	// Only Sara may decide, and with a fresh second factor once she has one.
	_, hana := tn.signInSession("hana@example.com", "some-password")
	if r := tn.front("POST", "/v1/me/approvals/"+c.ApprovalID+"/approve", nil, hana); r.code() != "not_your_approval" {
		t.Fatalf("hana approves: %d %s", r.Status, r.Raw)
	}
	app, _ := enrollTOTP(t, tn, sara)
	w.e.clock.advance(6 * time.Minute)
	if r := tn.front("POST", "/v1/me/approvals/"+c.ApprovalID+"/approve", nil, sara); r.code() != "step_up_required" {
		t.Fatalf("approve with a stale factor: %d %s", r.Status, r.Raw)
	}
	tn.front("POST", "/v1/step-up", obj{"code": app.code()}, sara)
	if r := tn.front("POST", "/v1/me/approvals/"+c.ApprovalID+"/approve", nil, sara); r.Status != 200 {
		t.Fatalf("approve: %d %s", r.Status, r.Raw)
	}
	// The agent sees the outcome, then acts once with the exact values.
	var state struct {
		Status string `json:"status"`
	}
	tn.back("GET", "/v1/approvals/"+c.ApprovalID, nil).data(&state)
	if state.Status != "approved" {
		t.Fatalf("approval state: %+v", state)
	}
	if other := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.payout", "resource": obj{"type": "organization", "id": "merchant-b"}, "details": obj{"amount": 9000, "to": "acct-9"}, "approval_id": c.ApprovalID}); other.Allowed || other.Reason != "approval_invalid" {
		t.Fatalf("other values: %+v", other)
	}
	if done := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.payout", "resource": obj{"type": "organization", "id": "merchant-b"}, "details": details, "approval_id": c.ApprovalID}); !done.Allowed || done.Reason != "approved" {
		t.Fatalf("approved action: %+v", done)
	}
	if twice := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.payout", "resource": obj{"type": "organization", "id": "merchant-b"}, "details": details, "approval_id": c.ApprovalID}); twice.Allowed {
		t.Fatal("an approval worked twice")
	}
	// Declining.
	d := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.payout", "resource": obj{"type": "organization", "id": "merchant-b"}, "details": obj{"amount": 1}})
	tn.front("POST", "/v1/me/approvals/"+d.ApprovalID+"/decline", nil, sara)
	if dd := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.payout", "resource": obj{"type": "organization", "id": "merchant-b"}, "details": obj{"amount": 1}, "approval_id": d.ApprovalID}); dd.Allowed || dd.Reason != "approval_declined" {
		t.Fatalf("declined: %+v", dd)
	}

	// The agent's own grants: an agent with a direct grant asks its owner.
	w.grant(agent.ID, "Finance", "organization", "merchant-a", "allow")
	own := ask(obj{"principal_id": agent.ID, "permission": "payment.payout", "resource": obj{"type": "organization", "id": "merchant-a"}, "details": obj{"amount": 2}})
	if own.Allowed || own.Reason != "approval_required" {
		t.Fatalf("agent on its own: %+v", own)
	}
	tn.front("GET", "/v1/me/approvals", nil, sara).data(&pending)
	if len(pending) != 1 || pending[0].ID != own.ApprovalID {
		t.Fatalf("owner's approvals: %+v", pending)
	}
	// A person is never asked for approval.
	if p := ask(obj{"principal_id": w.sara, "permission": "payment.payout", "resource": obj{"type": "organization", "id": "merchant-b"}}); !p.Allowed {
		t.Fatalf("a person needs approval: %+v", p)
	}

	// The delegation expires. Then the kill switch removes everything.
	w.e.clock.advance(9 * time.Hour)
	if c := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.read", "resource": obj{"type": "branch", "id": "branch-1"}}); c.Allowed || c.Reason != "no_delegation" {
		t.Fatalf("expired delegation: %+v", c)
	}
	tn.front("POST", "/v1/me/delegations", obj{"agent_id": agent.ID, "scopes": []string{"payment.read"}, "resource": obj{"type": "organization", "id": "merchant-a"}, "hours": 8}, sara)
	tn.back("POST", "/v1/api-keys", obj{"principal_id": agent.ID, "name": "agent key"})
	var audit []struct {
		Action string `json:"action"`
	}
	tn.back("GET", "/v1/machines/"+agent.ID+"/audit", nil).data(&audit)
	if len(audit) == 0 {
		t.Fatal("no audit trail for the agent")
	}
	r = tn.back("POST", "/v1/machines/"+agent.ID+"/revoke", obj{"reason": "runaway loop"})
	if r.Status != 200 {
		t.Fatalf("revoke agent: %d %s", r.Status, r.Raw)
	}
	var revoked struct {
		Keys        int64 `json:"api_keys_revoked"`
		Delegations int64 `json:"delegations_revoked"`
		Grants      int64 `json:"grants_removed"`
	}
	r.data(&revoked)
	if revoked.Keys != 1 || revoked.Delegations < 1 || revoked.Grants != 1 {
		t.Fatalf("revoked: %+v", revoked)
	}
	if c := ask(obj{"principal_id": w.sara, "agent_id": agent.ID, "permission": "payment.read", "resource": obj{"type": "branch", "id": "branch-1"}}); c.Allowed || c.Reason != "principal_inactive" {
		t.Fatalf("revoked agent: %+v", c)
	}
	if c := ask(obj{"principal_id": agent.ID, "permission": "payment.read", "resource": obj{"type": "organization", "id": "merchant-a"}}); c.Allowed {
		t.Fatal("the revoked agent still holds a grant")
	}
}
