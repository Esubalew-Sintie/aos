package tests

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestImportUsersKeepsTheirPasswords(t *testing.T) {
	w := newWorld(t)
	tn := w.tn
	hash, _ := bcrypt.GenerateFromPassword([]byte("old-system-password"), 4)
	r := tn.back("POST", "/v1/import/users", obj{"users": []obj{
		{"email": "Moved@Example.com", "name": "Moved", "email_verified": true, "password_hash": string(hash),
			"roles": []obj{{"role": "Finance", "resource": obj{"type": "organization", "id": "merchant-a"}}}},
		{"email": "nohash@example.com", "email_verified": true},
		{"email": "hana@example.com"},
		{"email": "weird@example.com", "password_hash": "$md5$nope"},
		{"email": "badrole@example.com", "roles": []obj{{"role": "Nope", "resource": obj{"type": "tenant", "id": "root"}}}},
	}})
	if r.Status != 200 {
		t.Fatalf("import: %d %s", r.Status, r.Raw)
	}
	var res struct {
		Created int               `json:"created"`
		IDs     map[string]string `json:"ids"`
		Skipped []struct {
			Email  string `json:"email"`
			Reason string `json:"reason"`
		} `json:"skipped"`
	}
	r.data(&res)
	if res.Created != 2 || len(res.Skipped) != 3 {
		t.Fatalf("import result: %s", r.Raw)
	}
	moved := res.IDs["moved@example.com"]
	if ok, _ := w.can(moved, "payment.refund", "branch", "branch-1"); !ok {
		t.Fatal("the imported role does not hold")
	}
	// The old bcrypt hash signs in, and is replaced by Argon2id.
	if r := tn.signIn("moved@example.com", "old-system-password"); r.Status != 200 {
		t.Fatalf("sign in with an imported hash: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.passwords WHERE principal_id = $1 AND hash LIKE '$argon2id$%'`, moved); n != 1 {
		t.Fatal("the imported hash was not upgraded")
	}
	if r := tn.signIn("moved@example.com", "old-system-password"); r.Status != 200 {
		t.Fatal("the upgraded hash does not work")
	}
	if r := tn.signIn("moved@example.com", "wrong"); r.Status == 200 {
		t.Fatal("a wrong password worked")
	}
}

func TestTenantArchiveMovesEverything(t *testing.T) {
	w := newWorld(t)
	src := w.tn
	e := w.e
	// Some state worth moving: a step-up permission, a group, a second factor.
	w.ok(src.back("PUT", "/v1/permissions", obj{"name": "payment.refund", "step_up_seconds": 300}))
	var group struct {
		ID string `json:"id"`
	}
	src.back("PUT", "/v1/groups", obj{"name": "Auditors"}).data(&group)
	src.back("POST", "/v1/groups/"+group.ID+"/members", obj{"principal_id": w.daniel})
	w.grant("", "Finance", "organization", "merchant-b", "allow", obj{"group_id": group.ID})
	_, sara := src.signInSession("sara@example.com", "some-password")
	app, _ := enrollTOTP(t, src, sara)

	if r := src.back("POST", "/v1/export", obj{"passphrase": "short"}); r.Status != 400 {
		t.Fatalf("short passphrase: %d", r.Status)
	}
	r := src.back("POST", "/v1/export", obj{"passphrase": "a long archive passphrase"})
	if r.Status != 200 {
		t.Fatalf("export: %d %s", r.Status, r.Raw)
	}
	var archive struct {
		Archive string         `json:"archive"`
		Counts  map[string]int `json:"counts"`
	}
	r.data(&archive)
	if archive.Counts["principals"] != 3 || strings.Contains(archive.Archive, "sara@example.com") {
		t.Fatalf("archive: %v (plain text inside: %v)", archive.Counts, strings.Contains(archive.Archive, "sara"))
	}

	// A new, empty home.
	dst := e.tenant("paygate-new")
	if r := dst.back("POST", "/v1/import/archive", obj{"archive": archive.Archive, "passphrase": "the wrong passphrase"}); r.code() != "invalid_archive" {
		t.Fatalf("wrong passphrase: %d %s", r.Status, r.Raw)
	}
	r = dst.back("POST", "/v1/import/archive", obj{"archive": archive.Archive, "passphrase": "a long archive passphrase"})
	if r.Status != 200 {
		t.Fatalf("import: %d %s", r.Status, r.Raw)
	}
	// Passwords survive; the second factor survives; sessions do not.
	if r := dst.front("GET", "/v1/session", nil, sara); r.Status != 401 {
		t.Fatal("a session moved with the archive")
	}
	if r := dst.signIn("hana@example.com", "some-password"); r.Status != 200 {
		t.Fatalf("hana in the new home: %d %s", r.Status, r.Raw)
	}
	var pending pendingData
	dst.signIn("sara@example.com", "some-password").data(&pending)
	if !pending.SecondFactorRequired {
		t.Fatal("sara's second factor did not move")
	}
	if r := dst.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "totp", "code": app.code()}, ""); r.Status != 200 {
		t.Fatalf("sara's authenticator in the new home: %d %s", r.Status, r.Raw)
	}
	// Grants, denies, groups and the tree all hold.
	saraNew := userID(t, dst, "sara@example.com")
	danielNew := userID(t, dst, "daniel@example.com")
	ask := func(principal, permission, typ, id string) bool {
		var out struct {
			Allowed bool `json:"allowed"`
		}
		dst.back("POST", "/v1/can", obj{"principal_id": principal, "permission": permission, "resource": obj{"type": typ, "id": id}}).data(&out)
		return out.Allowed
	}
	if !ask(saraNew, "payment.read", "branch", "branch-1") || ask(saraNew, "payment.read", "organization", "merchant-b") {
		t.Fatal("sara's grants did not move")
	}
	if ask(danielNew, "payment.refund", "branch", "branch-1") {
		t.Fatal("a permission appeared from nowhere")
	}
	if !ask(danielNew, "payment.read", "organization", "merchant-b") {
		t.Fatal("the group grant did not move")
	}
	// The step-up rule moved with the permission.
	var reason struct {
		Reason string `json:"reason"`
	}
	dst.back("POST", "/v1/can", obj{"principal_id": userID(t, dst, "hana@example.com"), "permission": "payment.refund", "resource": obj{"type": "branch", "id": "branch-1"}}).data(&reason)
	if reason.Reason != "step_up_required" {
		t.Fatalf("step-up did not move: %s", reason.Reason)
	}
	// The new chain names the old one; a second import is refused.
	if n := dst.count(`SELECT count(*) FROM aos.audit_log WHERE action = 'tenant.imported' AND data ? 'previous_audit_head'`); n != 1 {
		t.Fatal("the new audit chain does not name the old one")
	}
	if r := dst.back("POST", "/v1/import/archive", obj{"archive": archive.Archive, "passphrase": "a long archive passphrase"}); r.code() != "tenant_not_empty" {
		t.Fatalf("second import: %d %s", r.Status, r.Raw)
	}
}

func TestAccessReviews(t *testing.T) {
	w := newWorld(t)
	tn := w.tn
	var orgID string
	_ = orgID
	// Merchant A was made as a resource only; make it an organization.
	_, hana := tn.signInSession("hana@example.com", "some-password")
	org := createOrg(t, tn, hana, "Merchant Z")
	w.grant(w.sara, "Finance", "organization", org.Slug, "allow")
	w.grant(w.daniel, "Cashier", "organization", org.Slug, "allow")

	_, sara := tn.signInSession("sara@example.com", "some-password")
	if r := tn.front("POST", "/v1/access-reviews", obj{"organization_id": org.ID}, sara); r.Status != 403 {
		t.Fatalf("finance starts a review: %d %s", r.Status, r.Raw)
	}
	r := tn.front("POST", "/v1/access-reviews", obj{"organization_id": org.ID, "due_days": 14}, hana)
	if r.Status != 201 {
		t.Fatalf("start review: %d %s", r.Status, r.Raw)
	}
	var review struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		Undecided int    `json:"undecided"`
		Items     []struct {
			ID   string `json:"id"`
			Who  string `json:"who"`
			Role string `json:"role"`
		} `json:"items"`
	}
	r.data(&review)
	if review.Undecided != 3 || len(review.Items) != 3 {
		t.Fatalf("review: %s", r.Raw)
	}
	for _, it := range review.Items {
		decision := "keep"
		if it.Who == "daniel@example.com" {
			decision = "remove"
		}
		r = tn.front("POST", "/v1/access-reviews/"+review.ID+"/items/"+it.ID, obj{"decision": decision}, hana)
		if r.Status != 200 {
			t.Fatalf("decide: %d %s", r.Status, r.Raw)
		}
	}
	r.data(&review)
	if review.Status != "completed" || review.Undecided != 0 {
		t.Fatalf("after deciding: %s", r.Raw)
	}
	if ok, _ := w.can(w.daniel, "payment.read", "organization", org.Slug); ok {
		t.Fatal("a removed grant survived the review")
	}
	if ok, _ := w.can(w.sara, "payment.read", "organization", org.Slug); !ok {
		t.Fatal("a kept grant was removed")
	}
	if r := tn.front("POST", "/v1/access-reviews/"+review.ID+"/items/"+review.Items[0].ID, obj{"decision": "keep"}, hana); r.code() != "review_completed" {
		t.Fatalf("decide after completion: %d %s", r.Status, r.Raw)
	}
	var list []struct {
		ID string `json:"id"`
	}
	tn.back("GET", "/v1/admin/organizations/"+org.ID+"/access-reviews", nil).data(&list)
	if len(list) != 1 {
		t.Fatalf("reviews: %+v", list)
	}
	if n := tn.count(`SELECT count(*) FROM aos.audit_log WHERE reason_code = 'access_review'`); n != 1 {
		t.Fatalf("review removals in the audit log: %d", n)
	}
}
