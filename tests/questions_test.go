package tests

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// can asks the permission question through the backend door.
func can(t *testing.T, tn *tenant, principal, permission, resType, resID string) (bool, string) {
	t.Helper()
	r := tn.back("POST", "/v1/can", obj{
		"principal_id": principal, "permission": permission, "resource": obj{"type": resType, "id": resID},
	})
	if r.Status != 200 {
		t.Fatalf("can: %d %s", r.Status, r.Raw)
	}
	var out struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	r.data(&out)
	return out.Allowed, out.Reason
}

// userID finds a person's id by email.
func userID(t *testing.T, tn *tenant, email string) string {
	t.Helper()
	var id string
	tn.sql(func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT principal_id::text FROM aos.users WHERE email = $1`, email).Scan(&id)
	})
	return id
}

// claims decodes the payload of a JWT without checking it.
func claims(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestCanBatchAnswersEveryQuestion(t *testing.T) {
	w := newWorld(t)
	ask := func(principal, permission, resType, resID string) obj {
		return obj{"principal_id": principal, "permission": permission, "resource": obj{"type": resType, "id": resID}}
	}
	r := w.tn.back("POST", "/v1/can/batch", obj{"checks": []obj{
		ask(w.sara, "payment.refund", "branch", "branch-1"),
		ask(w.sara, "payment.refund", "branch", "branch-2"),
		ask(w.daniel, "payment.refund", "branch", "branch-1"),
		ask(w.daniel, "payment.create", "branch", "nowhere"),
	}})
	if r.Status != 200 {
		t.Fatalf("batch: %d %s", r.Status, r.Raw)
	}
	var out struct {
		Results []struct {
			Allowed bool   `json:"allowed"`
			Reason  string `json:"reason"`
		} `json:"results"`
	}
	r.data(&out)
	want := []struct {
		allowed bool
		reason  string
	}{{true, "allowed"}, {false, "denied_by_grant"}, {false, "no_matching_grant"}, {false, "unknown_resource"}}
	if len(out.Results) != len(want) {
		t.Fatalf("results: %+v", out.Results)
	}
	for i, res := range out.Results {
		if res.Allowed != want[i].allowed || res.Reason != want[i].reason {
			t.Fatalf("result %d: %+v, want %+v", i, res, want[i])
		}
	}
	if r := w.tn.back("POST", "/v1/can/batch", obj{"checks": []obj{}}); r.Status != 400 {
		t.Fatalf("empty batch: %d", r.Status)
	}
}

func TestExplainShowsThePath(t *testing.T) {
	w := newWorld(t)
	r := w.tn.back("POST", "/v1/explain", obj{
		"principal_id": w.sara, "permission": "payment.refund", "resource": obj{"type": "branch", "id": "branch-2"},
	})
	if r.Status != 200 {
		t.Fatalf("explain: %d %s", r.Status, r.Raw)
	}
	var out struct {
		Allowed   bool `json:"allowed"`
		Reason    string
		DecidedBy *struct {
			Role   string `json:"role"`
			Effect string `json:"effect"`
			Depth  int    `json:"depth"`
		} `json:"decided_by"`
		LookedAt []struct {
			Type       string `json:"type"`
			ExternalID string `json:"external_id"`
		} `json:"looked_at"`
		Matched []struct {
			Role   string `json:"role"`
			Effect string `json:"effect"`
		} `json:"matched"`
	}
	r.data(&out)
	if out.Allowed || out.DecidedBy == nil || out.DecidedBy.Role != "Refunds" || out.DecidedBy.Effect != "deny" || out.DecidedBy.Depth != 0 {
		t.Fatalf("decided by: %+v", out)
	}
	// Branch 2, Merchant A, the root: the path that was looked at.
	if len(out.LookedAt) != 3 || out.LookedAt[0].ExternalID != "branch-2" || out.LookedAt[1].ExternalID != "merchant-a" || out.LookedAt[2].Type != "tenant" {
		t.Fatalf("looked at: %+v", out.LookedAt)
	}
	// Both the deny on the branch and the Finance allow above matched.
	if len(out.Matched) != 2 {
		t.Fatalf("matched: %+v", out.Matched)
	}
	// An unknown principal explains itself.
	r = w.tn.back("POST", "/v1/explain", obj{
		"principal_id": "00000000-0000-0000-0000-000000000000", "permission": "payment.refund", "resource": obj{"type": "branch", "id": "branch-2"},
	})
	r.data(&out)
	if out.Allowed || out.Reason != "unknown_principal" {
		t.Fatalf("unknown principal: %s", r.Raw)
	}
}

func TestFilterListsWhereAPermissionHolds(t *testing.T) {
	w := newWorld(t)
	filter := func(principal, permission, resType string) (allowed []string, truncated bool) {
		t.Helper()
		r := w.tn.back("POST", "/v1/filter", obj{"principal_id": principal, "permission": permission, "resource_type": resType})
		if r.Status != 200 {
			t.Fatalf("filter: %d %s", r.Status, r.Raw)
		}
		var out struct {
			Allowed   []string `json:"allowed"`
			Truncated bool     `json:"truncated"`
		}
		r.data(&out)
		return out.Allowed, out.Truncated
	}
	// Sara may refund at branch 1 (through Merchant A), not at branch 2 (denied).
	if got, _ := filter(w.sara, "payment.refund", "branch"); strings.Join(got, ",") != "branch-1" {
		t.Fatalf("sara's branches: %v", got)
	}
	// She may read payments at both.
	if got, _ := filter(w.sara, "payment.read", "branch"); len(got) != 2 {
		t.Fatalf("sara reads at: %v", got)
	}
	// Daniel only at his own branch, and Hana at both through the organization.
	if got, _ := filter(w.daniel, "payment.create", "branch"); strings.Join(got, ",") != "branch-1" {
		t.Fatalf("daniel's branches: %v", got)
	}
	if got, _ := filter(w.hana, "anything.at.all", "branch"); len(got) != 2 {
		t.Fatalf("hana's branches: %v", got)
	}
	// Organizations: Hana owns one, not the other.
	if got, _ := filter(w.hana, "payment.read", "organization"); strings.Join(got, ",") != "merchant-a" {
		t.Fatalf("hana's organizations: %v", got)
	}
	// A suspended person sees nothing.
	w.ok(w.tn.back("POST", "/v1/users/"+w.hana+"/suspend", obj{"reason": "test"}))
	if got, _ := filter(w.hana, "payment.read", "branch"); len(got) != 0 {
		t.Fatalf("suspended hana's branches: %v", got)
	}
}

func TestListPrincipalsSaysWhoMay(t *testing.T) {
	w := newWorld(t)
	who := func(permission, resType, resID string) []string {
		t.Helper()
		r := w.tn.back("POST", "/v1/principals", obj{"permission": permission, "resource": obj{"type": resType, "id": resID}})
		if r.Status != 200 {
			t.Fatalf("principals: %d %s", r.Status, r.Raw)
		}
		var out struct {
			Principals []struct {
				Email   string `json:"email"`
				Through struct {
					Role string `json:"role"`
				} `json:"through"`
			} `json:"principals"`
		}
		r.data(&out)
		var emails []string
		for _, p := range out.Principals {
			emails = append(emails, p.Email+":"+p.Through.Role)
		}
		return emails
	}
	// Refund at branch 2: Hana (Owner above). Sara is denied there.
	if got := who("payment.refund", "branch", "branch-2"); strings.Join(got, " ") != "hana@example.com:Owner" {
		t.Fatalf("refund at branch 2: %v", got)
	}
	// Create at branch 1: Hana, Sara, Daniel.
	if got := who("payment.create", "branch", "branch-1"); len(got) != 3 {
		t.Fatalf("create at branch 1: %v", got)
	}
	if r := w.tn.back("POST", "/v1/principals", obj{"permission": "payment.create", "resource": obj{"type": "branch", "id": "nowhere"}}); r.Status != 404 {
		t.Fatalf("unknown resource: %d", r.Status)
	}
}

func TestSimulateSaysWhoWouldLoseWhat(t *testing.T) {
	w := newWorld(t)
	// Give Sara Refunds at branch 1 too. Removing her Finance grant would
	// take payment.read and payment.create from her at Merchant A, while
	// payment.refund... also goes at the organization level, since the
	// Refunds grant is on branch 1, not on the organization.
	finance := w.grant(w.sara, "Cashier", "organization", "merchant-a", "allow")
	r := w.tn.back("POST", "/v1/simulate", obj{"grant_id": finance})
	if r.Status != 200 {
		t.Fatalf("simulate: %d %s", r.Status, r.Raw)
	}
	var out struct {
		Grant struct {
			Role string `json:"role"`
		} `json:"grant"`
		Affected []struct {
			PrincipalID  string `json:"principal_id"`
			Permission   string `json:"permission"`
			StillAllowed bool   `json:"still_allowed"`
		} `json:"affected"`
	}
	r.data(&out)
	if out.Grant.Role != "Cashier" || len(out.Affected) != 2 {
		t.Fatalf("simulate: %s", r.Raw)
	}
	// Finance (payment.*) still covers both, so nothing is lost.
	for _, a := range out.Affected {
		if a.PrincipalID != w.sara || !a.StillAllowed {
			t.Fatalf("affected: %+v", a)
		}
	}
	// Daniel's Cashier grant at branch 1 is his only one: both go.
	var daniel string
	w.tn.sql(func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT id::text FROM aos.grants WHERE principal_id = $1`, w.daniel).Scan(&daniel)
	})
	w.tn.back("POST", "/v1/simulate", obj{"grant_id": daniel}).data(&out)
	if len(out.Affected) != 2 || out.Affected[0].StillAllowed || out.Affected[1].StillAllowed {
		t.Fatalf("daniel: %+v", out.Affected)
	}
	// Nothing changed.
	if ok, _ := w.can(w.daniel, "payment.read", "branch", "branch-1"); !ok {
		t.Fatal("simulate changed something")
	}
	if r := w.tn.back("POST", "/v1/simulate", obj{"grant_id": "00000000-0000-0000-0000-000000000000"}); r.Status != 404 {
		t.Fatalf("unknown grant: %d", r.Status)
	}
}

func TestGroupsHoldGrantsForTheirMembers(t *testing.T) {
	w := newWorld(t)
	r := w.tn.back("PUT", "/v1/groups", obj{"name": "Auditors"})
	if r.Status != 200 {
		t.Fatalf("put group: %d %s", r.Status, r.Raw)
	}
	var group struct {
		ID          string `json:"id"`
		MemberCount int    `json:"member_count"`
	}
	r.data(&group)

	// A grant to the group, then Daniel joins it.
	w.ok(w.tn.back("PUT", "/v1/roles", obj{"name": "Auditor", "permissions": []string{"payment.read", "audit.read"}}))
	gid := w.grant("", "Auditor", "organization", "merchant-b", "allow", obj{"group_id": group.ID})
	if ok, _ := w.can(w.daniel, "audit.read", "organization", "merchant-b"); ok {
		t.Fatal("daniel holds a group permission before joining")
	}
	if r := w.tn.back("POST", "/v1/groups/"+group.ID+"/members", obj{"principal_id": w.daniel}); r.Status != 200 {
		t.Fatalf("add member: %d %s", r.Status, r.Raw)
	}
	if ok, _ := w.can(w.daniel, "audit.read", "organization", "merchant-b"); !ok {
		t.Fatal("group grant does not reach the member")
	}
	// The group shows its member count, and the grant explains itself.
	var groups []struct {
		Name        string `json:"name"`
		MemberCount int    `json:"member_count"`
	}
	w.tn.back("GET", "/v1/groups", nil).data(&groups)
	if len(groups) != 1 || groups[0].MemberCount != 1 {
		t.Fatalf("groups: %+v", groups)
	}
	var explain struct {
		DecidedBy *struct {
			GrantID string `json:"grant_id"`
		} `json:"decided_by"`
	}
	w.tn.back("POST", "/v1/explain", obj{
		"principal_id": w.daniel, "permission": "audit.read", "resource": obj{"type": "organization", "id": "merchant-b"},
	}).data(&explain)
	if explain.DecidedBy == nil || explain.DecidedBy.GrantID != gid {
		t.Fatalf("explain through the group: %+v", explain)
	}
	// Listing who may, and simulating the group grant, both see Daniel.
	var who struct {
		Principals []struct {
			ID string `json:"id"`
		} `json:"principals"`
	}
	w.tn.back("POST", "/v1/principals", obj{"permission": "audit.read", "resource": obj{"type": "organization", "id": "merchant-b"}}).data(&who)
	if len(who.Principals) != 1 || who.Principals[0].ID != w.daniel {
		t.Fatalf("who may audit: %+v", who.Principals)
	}
	var sim struct {
		Affected []struct {
			PrincipalID string `json:"principal_id"`
		} `json:"affected"`
	}
	w.tn.back("POST", "/v1/simulate", obj{"grant_id": gid}).data(&sim)
	if len(sim.Affected) != 2 || sim.Affected[0].PrincipalID != w.daniel {
		t.Fatalf("simulate the group grant: %+v", sim.Affected)
	}
	// Leaving the group takes the permission away. Deleting the group
	// takes its grants with it.
	if r := w.tn.back("DELETE", "/v1/groups/"+group.ID+"/members/"+w.daniel, nil); r.Status != 200 {
		t.Fatalf("remove member: %d %s", r.Status, r.Raw)
	}
	if ok, _ := w.can(w.daniel, "audit.read", "organization", "merchant-b"); ok {
		t.Fatal("permission survived leaving the group")
	}
	w.tn.back("POST", "/v1/groups/"+group.ID+"/members", obj{"principal_id": w.daniel})
	if r := w.tn.back("DELETE", "/v1/groups/"+group.ID, nil); r.Status != 200 {
		t.Fatalf("delete group: %d %s", r.Status, r.Raw)
	}
	if ok, _ := w.can(w.daniel, "audit.read", "organization", "merchant-b"); ok {
		t.Fatal("permission survived deleting the group")
	}
	if n := w.tn.count(`SELECT count(*) FROM aos.grants WHERE id = $1`, gid); n != 0 {
		t.Fatal("the group's grant survived")
	}
	// Bad input.
	if r := w.tn.back("POST", "/v1/grants", obj{"principal_id": w.daniel, "group_id": group.ID, "role": "Auditor", "resource": obj{"type": "organization", "id": "merchant-b"}}); r.Status != 400 {
		t.Fatalf("both principal and group: %d", r.Status)
	}
	if r := w.tn.back("PUT", "/v1/groups", obj{"name": "Nope", "organization_id": "00000000-0000-0000-0000-000000000000"}); r.Status != 400 {
		t.Fatalf("group in an unknown organization: %d", r.Status)
	}
}
