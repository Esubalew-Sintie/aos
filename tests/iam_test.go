package tests

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
)

// world is the payment-gateway example from the user flows:
//
//	tenant root
//	├── Merchant A (organization)
//	│   ├── Branch 1
//	│   └── Branch 2
//	└── Merchant B (organization)
//
// Hana owns Merchant A. Sara is Finance there, and is denied refunds at
// Branch 2. Daniel is a cashier at Branch 1.
type world struct {
	e                  *env
	tn                 *tenant
	hana, sara, daniel string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	e := newEnv(t)
	tn := e.tenant("paygate")
	w := &world{e: e, tn: tn}
	w.hana, _ = tn.user("hana@example.com", "some-password")
	w.sara, _ = tn.user("sara@example.com", "some-password")
	w.daniel, _ = tn.user("daniel@example.com", "some-password")

	for _, p := range []string{"payment.read", "payment.create", "payment.refund"} {
		w.ok(tn.back("PUT", "/v1/permissions", obj{"name": p}))
	}
	w.ok(tn.back("PUT", "/v1/roles", obj{"name": "Finance", "permissions": []string{"payment.*"}}))
	w.ok(tn.back("PUT", "/v1/roles", obj{"name": "Cashier", "permissions": []string{"payment.read", "payment.create"}}))
	w.ok(tn.back("PUT", "/v1/roles", obj{"name": "Refunds", "permissions": []string{"payment.refund"}}))

	w.ok(tn.back("PUT", "/v1/resources", obj{"type": "organization", "id": "merchant-a"}))
	w.ok(tn.back("PUT", "/v1/resources", obj{"type": "organization", "id": "merchant-b"}))
	merchantA := obj{"type": "organization", "id": "merchant-a"}
	w.ok(tn.back("PUT", "/v1/resources", obj{"type": "branch", "id": "branch-1", "parent": merchantA}))
	w.ok(tn.back("PUT", "/v1/resources", obj{"type": "branch", "id": "branch-2", "parent": merchantA}))

	w.grant(w.hana, "Owner", "organization", "merchant-a", "allow")
	w.grant(w.sara, "Finance", "organization", "merchant-a", "allow")
	w.grant(w.daniel, "Cashier", "branch", "branch-1", "allow")
	w.grant(w.sara, "Refunds", "branch", "branch-2", "deny")
	return w
}

func (w *world) ok(r result) result {
	w.e.t.Helper()
	if r.Status < 200 || r.Status > 299 {
		w.e.t.Fatalf("setup call failed: %d %s", r.Status, r.Raw)
	}
	return r
}

// grant gives a role and returns the id of the grant.
func (w *world) grant(principal, role, resType, resID, effect string, extra ...obj) string {
	w.e.t.Helper()
	body := obj{"role": role, "effect": effect, "resource": obj{"type": resType, "id": resID}}
	if principal != "" {
		body["principal_id"] = principal
	}
	for _, x := range extra {
		for k, v := range x {
			body[k] = v
		}
	}
	var out struct {
		ID string `json:"id"`
	}
	w.ok(w.tn.back("POST", "/v1/grants", body)).data(&out)
	return out.ID
}

// can asks the question and returns the answer and its reason.
func (w *world) can(principal, permission, resType, resID string) (bool, string) {
	w.e.t.Helper()
	r := w.tn.back("POST", "/v1/can", obj{
		"principal_id": principal, "permission": permission, "resource": obj{"type": resType, "id": resID},
	})
	if r.Status != 200 {
		w.e.t.Fatalf("can: %d %s", r.Status, r.Raw)
	}
	var out struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	r.data(&out)
	return out.Allowed, out.Reason
}

func TestPermissionDecisions(t *testing.T) {
	w := newWorld(t)
	const nobody = "00000000-0000-0000-0000-000000000000"

	cases := []struct {
		name       string
		who        string
		permission string
		resType    string
		resID      string
		allowed    bool
		reason     string
	}{
		{"a grant reaches everything beneath it, and a prefix matches",
			w.sara, "payment.refund", "branch", "branch-1", true, "allowed"},
		{"the default is deny",
			w.daniel, "payment.refund", "branch", "branch-1", false, "no_matching_grant"},
		{"a role allows what it holds",
			w.daniel, "payment.create", "branch", "branch-1", true, "allowed"},
		{"a grant on one branch gives nothing on another",
			w.daniel, "payment.create", "branch", "branch-2", false, "no_matching_grant"},
		{"a grant on a child gives nothing on its parent",
			w.daniel, "payment.create", "organization", "merchant-a", false, "no_matching_grant"},
		{"deny beats allow",
			w.sara, "payment.refund", "branch", "branch-2", false, "denied_by_grant"},
		{"a deny covers only what its role holds",
			w.sara, "payment.read", "branch", "branch-2", true, "allowed"},
		{"Owner holds every permission, even one nobody declared",
			w.hana, "anything.at_all", "branch", "branch-2", true, "allowed"},
		{"Owner of one organization has nothing in another",
			w.hana, "payment.read", "organization", "merchant-b", false, "no_matching_grant"},
		{"Owner of an organization has nothing on the tenant root",
			w.hana, "payment.read", "tenant", "root", false, "no_matching_grant"},
		{"an unknown principal is denied",
			nobody, "payment.read", "branch", "branch-1", false, "unknown_principal"},
		{"an unknown resource is denied",
			w.hana, "payment.read", "branch", "no-such-branch", false, "unknown_resource"},
	}
	for _, c := range cases {
		allowed, reason := w.can(c.who, c.permission, c.resType, c.resID)
		if allowed != c.allowed || reason != c.reason {
			t.Errorf("%s: got (%v, %s), want (%v, %s)", c.name, allowed, reason, c.allowed, c.reason)
		}
	}
}

// Deny beats allow even for an Owner. There is no bypass in the code.
func TestDenyBeatsOwner(t *testing.T) {
	w := newWorld(t)
	if allowed, _ := w.can(w.hana, "payment.refund", "branch", "branch-2"); !allowed {
		t.Fatal("setup: the Owner should be allowed before the deny")
	}
	w.grant(w.hana, "Refunds", "branch", "branch-2", "deny")
	if allowed, reason := w.can(w.hana, "payment.refund", "branch", "branch-2"); allowed || reason != "denied_by_grant" {
		t.Fatalf("an Owner got past a deny: (%v, %s)", allowed, reason)
	}
	if allowed, _ := w.can(w.hana, "payment.refund", "branch", "branch-1"); !allowed {
		t.Fatal("the deny on one branch reached another")
	}
}

func TestGrantsExpireAndCanBeRemoved(t *testing.T) {
	w := newWorld(t)

	// A grant with an expiry stops matching by itself.
	w.grant(w.daniel, "Refunds", "branch", "branch-1", "allow",
		obj{"expires_at": w.e.clock.Now().Add(time.Hour), "reason": "covering for a colleague"})
	if allowed, _ := w.can(w.daniel, "payment.refund", "branch", "branch-1"); !allowed {
		t.Fatal("a temporary grant did not take effect")
	}
	w.e.clock.advance(2 * time.Hour)
	if allowed, reason := w.can(w.daniel, "payment.refund", "branch", "branch-1"); allowed || reason != "no_matching_grant" {
		t.Fatalf("an expired grant still matches: (%v, %s)", allowed, reason)
	}

	// Removing a grant takes effect on the next check.
	id := w.grant(w.daniel, "Refunds", "branch", "branch-1", "allow")
	if allowed, _ := w.can(w.daniel, "payment.refund", "branch", "branch-1"); !allowed {
		t.Fatal("a new grant did not take effect")
	}
	if r := w.tn.back("DELETE", "/v1/grants/"+id, nil); r.Status != 200 {
		t.Fatalf("delete grant: %d %s", r.Status, r.Raw)
	}
	if allowed, _ := w.can(w.daniel, "payment.refund", "branch", "branch-1"); allowed {
		t.Fatal("a removed grant still matches")
	}
	if r := w.tn.back("DELETE", "/v1/grants/"+id, nil); r.Status != 404 {
		t.Fatalf("deleting a grant twice: %d %s", r.Status, r.Raw)
	}
	if r := w.tn.back("DELETE", "/v1/grants/not-an-id", nil); r.Status != 404 {
		t.Fatalf("deleting a grant with a bad id: %d %s", r.Status, r.Raw)
	}
}

func TestSuspendedPrincipalIsDeniedEverything(t *testing.T) {
	w := newWorld(t)
	w.tn.sql(func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE aos.principals SET status = 'suspended' WHERE id = $1`, w.hana)
		return err
	})
	if allowed, reason := w.can(w.hana, "payment.read", "organization", "merchant-a"); allowed || reason != "principal_inactive" {
		t.Fatalf("a suspended Owner is still allowed: (%v, %s)", allowed, reason)
	}
}

// Owner is the one role AOS ships. Nobody can empty it.
func TestOwnerRoleCannotBeChanged(t *testing.T) {
	w := newWorld(t)
	r := w.tn.back("PUT", "/v1/roles", obj{"name": "Owner", "permissions": []string{}})
	if r.Status != 409 || r.code() != "role_is_built_in" {
		t.Fatalf("changing Owner: %d %s", r.Status, r.Raw)
	}
	if allowed, _ := w.can(w.hana, "payment.refund", "branch", "branch-1"); !allowed {
		t.Fatal("the Owner role lost its permissions")
	}
}

func TestSavingARoleAgainChangesWhatItHolds(t *testing.T) {
	w := newWorld(t)
	if allowed, _ := w.can(w.sara, "payment.refund", "branch", "branch-1"); !allowed {
		t.Fatal("setup: Finance should allow refunds")
	}
	w.ok(w.tn.back("PUT", "/v1/roles", obj{"name": "Finance", "permissions": []string{"payment.read"}}))
	// Everyone who holds the role is affected on the next check.
	if allowed, _ := w.can(w.sara, "payment.refund", "branch", "branch-1"); allowed {
		t.Fatal("the role still allows what was removed from it")
	}
	if allowed, _ := w.can(w.sara, "payment.read", "branch", "branch-1"); !allowed {
		t.Fatal("the role lost what it still holds")
	}
}

func TestResourcesCanBeSavedAgainButNotMovedByAccident(t *testing.T) {
	w := newWorld(t)
	save := func(parent string) result {
		return w.tn.back("PUT", "/v1/resources", obj{
			"type": "branch", "id": "branch-1", "parent": obj{"type": "organization", "id": parent},
		})
	}
	var first, second struct {
		ID string `json:"id"`
	}
	w.ok(save("merchant-a")).data(&first)
	w.ok(save("merchant-a")).data(&second)
	if first.ID == "" || first.ID != second.ID {
		t.Fatalf("saving a resource twice made two: %q %q", first.ID, second.ID)
	}
	// The same resource under another parent is a mistake, not a move.
	if r := save("merchant-b"); r.Status != 409 || r.code() != "resource_exists_elsewhere" {
		t.Fatalf("saving under another parent: %d %s", r.Status, r.Raw)
	}
	if r := w.tn.back("PUT", "/v1/resources", obj{"type": "branch", "id": "x", "parent": obj{"type": "organization", "id": "nope"}}); r.Status != 400 {
		t.Fatalf("an unknown parent: %d %s", r.Status, r.Raw)
	}
	if r := w.tn.back("PUT", "/v1/resources", obj{"type": "tenant", "id": "second-root"}); r.Status != 400 {
		t.Fatalf("a second root: %d %s", r.Status, r.Raw)
	}
}

func TestGrantRequestsAreChecked(t *testing.T) {
	w := newWorld(t)
	root := obj{"type": "tenant", "id": "root"}
	cases := map[string]struct {
		body  obj
		field string
	}{
		"unknown role":     {obj{"principal_id": w.hana, "role": "Nope", "resource": root}, "role"},
		"unknown resource": {obj{"principal_id": w.hana, "role": "Cashier", "resource": obj{"type": "branch", "id": "nope"}}, "resource"},
		"bad effect":       {obj{"principal_id": w.hana, "role": "Cashier", "resource": root, "effect": "maybe"}, "effect"},
		"past expiry":      {obj{"principal_id": w.hana, "role": "Cashier", "resource": root, "expires_at": time.Now().Add(-time.Hour)}, "expires_at"},
		"bad principal id": {obj{"principal_id": "hana", "role": "Cashier", "resource": root}, "principal_id"},
	}
	for name, c := range cases {
		r := w.tn.back("POST", "/v1/grants", c.body)
		if r.Status != 400 || r.Body.Error == nil || r.Body.Error.Details[c.field] == "" {
			t.Errorf("%s: got %d %s, want 400 naming %q", name, r.Status, r.Raw, c.field)
		}
	}
	for name, body := range map[string]obj{
		"bad permission name": {"name": "Payment Refund"},
		"bad role pattern":    {"name": "X", "permissions": []string{"payment.*.read"}},
	} {
		path := "/v1/permissions"
		if _, isRole := body["permissions"]; isRole {
			path = "/v1/roles"
		}
		if r := w.tn.back("PUT", path, body); r.Status != 400 {
			t.Errorf("%s: got %d %s, want 400", name, r.Status, r.Raw)
		}
	}
}

// Every deny is written to the decision log, and a check marks the
// permission as "in use".
func TestDeniesAreLogged(t *testing.T) {
	w := newWorld(t)
	if n := w.tn.count(`SELECT count(*) FROM aos.permissions WHERE name = 'payment.refund' AND last_checked_at IS NOT NULL`); n != 0 {
		t.Fatal("setup: the permission is already marked as checked")
	}
	before := w.tn.count(`SELECT count(*) FROM aos.decision_log WHERE decision = 'deny'`)
	w.can(w.daniel, "payment.refund", "branch", "branch-1")
	if after := w.tn.count(`SELECT count(*) FROM aos.decision_log WHERE decision = 'deny'`); after != before+1 {
		t.Fatalf("the deny was not logged: %d before, %d after", before, after)
	}
	if n := w.tn.count(`SELECT count(*) FROM aos.decision_log WHERE decision = 'deny' AND reason_code = 'no_matching_grant' AND principal_id = $1`, w.daniel); n != 1 {
		t.Fatalf("the logged deny does not name who and why: %d", n)
	}
	if n := w.tn.count(`SELECT count(*) FROM aos.permissions WHERE name = 'payment.refund' AND last_checked_at IS NOT NULL`); n != 1 {
		t.Fatal("the check did not mark the permission as in use")
	}
}

// A permission remembers whether it was made with the SDK or in the
// portal. Saving it again from the other side does not change that.
func TestPermissionRemembersWhereItWasCreated(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	tenantModel, _, err := w.e.app.Module.Tenant.ResolveKey(ctx, w.tn.PK)
	if err != nil {
		t.Fatal(err)
	}
	// As the tenant admin portal will: source "portal".
	if _, err := w.e.app.Module.IAM.PutPermission(ctx, tenantModel,
		requestPermission("report.export"), constant.SourcePortal, w.e.metaForTest()); err != nil {
		t.Fatal(err)
	}
	// Then the SDK declares the same name.
	var saved struct {
		Source string `json:"source"`
	}
	w.ok(w.tn.back("PUT", "/v1/permissions", obj{"name": "report.export", "description": "Export reports"})).data(&saved)
	if saved.Source != constant.SourcePortal {
		t.Fatalf("the permission forgot it was made in the portal: %q", saved.Source)
	}
	var fromCode struct {
		Source string `json:"source"`
	}
	w.ok(w.tn.back("PUT", "/v1/permissions", obj{"name": "payment.read"})).data(&fromCode)
	if fromCode.Source != constant.SourceCode {
		t.Fatalf("a permission made by the SDK should be marked code: %q", fromCode.Source)
	}
}

func requestPermission(name string) request.PutPermissionRequest {
	return request.PutPermissionRequest{Name: name}
}

// user-flow WHO-6: a tenant can give every new user a small default role.
// It is granted when the address is confirmed, and not before.
func TestDefaultRoleAtSignUp(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.ok(w.tn.back("PUT", "/v1/roles", obj{"name": "Customer", "permissions": []string{"wallet.read"}}))
	err := w.e.app.DB.Platform(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE aos.tenants t SET default_role_id = r.id
			FROM aos.roles r WHERE t.id = $1 AND r.tenant_id = t.id AND r.name = 'Customer'`, w.tn.ID)
		return err
	})
	// The platform role cannot read roles, so the statement above must fail
	// for it. The setting belongs to the tenant, and is written as the tenant.
	if sqlState(err) != permissionDenied {
		t.Fatalf("the platform role read a tenant's roles: %v", err)
	}
	w.tn.sql(func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE aos.tenants SET default_role_id = (SELECT id FROM aos.roles WHERE name = 'Customer')
			WHERE id = $1`, w.tn.ID)
		return err
	})

	newcomer, _ := w.tn.user("newcomer@example.com", "some-password")
	if allowed, _ := w.can(newcomer, "wallet.read", "tenant", "root"); !allowed {
		t.Fatal("a new user did not receive the default role")
	}
	if allowed, _ := w.can(newcomer, "payment.refund", "tenant", "root"); allowed {
		t.Fatal("the default role gave more than it holds")
	}
	// Someone who signed up before the setting existed is not affected.
	if allowed, _ := w.can(w.daniel, "wallet.read", "tenant", "root"); allowed {
		t.Fatal("the default role reached a user who signed up earlier")
	}
	// Signing in again does not hand it out a second time.
	w.tn.signIn("newcomer@example.com", "some-password")
	if n := w.tn.count(`SELECT count(*) FROM aos.grants WHERE principal_id = $1`, newcomer); n != 1 {
		t.Fatalf("want exactly 1 grant for the new user, got %d", n)
	}
}

func TestTheCatalogCanBeRead(t *testing.T) {
	w := newWorld(t)
	var perms []struct {
		Name   string `json:"name"`
		Source string `json:"source"`
	}
	w.ok(w.tn.back("GET", "/v1/permissions", nil)).data(&perms)
	found := map[string]string{}
	for _, p := range perms {
		found[p.Name] = p.Source
	}
	if found["payment.refund"] == "" {
		t.Fatalf("the declared permission is missing: %v", found)
	}
	var roles []struct {
		Name        string   `json:"name"`
		Source      string   `json:"source"`
		Permissions []string `json:"permissions"`
	}
	w.ok(w.tn.back("GET", "/v1/roles", nil)).data(&roles)
	var owner, finance bool
	for _, r := range roles {
		owner = owner || (r.Name == "Owner" && r.Source == "system" && len(r.Permissions) == 1 && r.Permissions[0] == "*")
		finance = finance || (r.Name == "Finance" && len(r.Permissions) > 0)
	}
	if !owner || !finance {
		t.Fatalf("roles: %+v", roles)
	}
	// The catalog is a backend route: a publishable key does not open it.
	if r := w.tn.e.call("GET", "/v1/roles", nil, "X-AOS-Publishable-Key", w.tn.PK); r.Status != 401 {
		t.Fatalf("with a publishable key: %d", r.Status)
	}
}
