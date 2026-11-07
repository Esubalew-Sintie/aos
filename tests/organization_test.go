package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
)

type orgData struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// createOrg makes an organization as a signed-in person and returns it.
func createOrg(t *testing.T, tn *tenant, session, name string) orgData {
	t.Helper()
	r := tn.front("POST", "/v1/organizations", obj{"name": name}, session)
	if r.Status != 201 {
		t.Fatalf("create organization: %d %s", r.Status, r.Raw)
	}
	var org orgData
	r.data(&org)
	return org
}

func TestSignedInPersonCreatesAndOwnsAnOrganization(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	hanaID, hana := tn.user("hana@example.com", "some-password")
	_, sara := tn.user("sara@example.com", "some-password")

	org := createOrg(t, tn, hana, "Merchant A")
	if org.Slug != "merchant-a" {
		t.Fatalf("slug: %q", org.Slug)
	}

	// The creator is the first owner, and the session now works in it.
	var members []struct {
		PrincipalID string   `json:"principal_id"`
		Roles       []string `json:"roles"`
	}
	tn.front("GET", "/v1/organizations/"+org.ID+"/members", nil, hana).data(&members)
	if len(members) != 1 || members[0].PrincipalID != hanaID || strings.Join(members[0].Roles, ",") != constant.RoleOwner {
		t.Fatalf("members: %+v", members)
	}
	var session struct {
		Session struct {
			ActiveOrganizationID string `json:"active_organization_id"`
			ActiveOrganization   string `json:"active_organization"`
		} `json:"session"`
	}
	tn.front("GET", "/v1/session", nil, hana).data(&session)
	if session.Session.ActiveOrganizationID != org.ID || session.Session.ActiveOrganization != "merchant-a" {
		t.Fatalf("active organization: %+v", session.Session)
	}
	var token struct {
		Token string `json:"token"`
	}
	tn.front("POST", "/v1/session/token", nil, hana).data(&token)
	if !strings.Contains(claims(t, token.Token), `"org":"merchant-a"`) {
		t.Fatalf("token lacks the org claim: %s", claims(t, token.Token))
	}

	// Hana sees her organization. Sara sees nothing, and gets "not found"
	// for Hana's, not "forbidden".
	var mine []orgData
	tn.front("GET", "/v1/organizations", nil, hana).data(&mine)
	if len(mine) != 1 || mine[0].ID != org.ID {
		t.Fatalf("hana's organizations: %+v", mine)
	}
	tn.front("GET", "/v1/organizations", nil, sara).data(&mine)
	if len(mine) != 0 {
		t.Fatalf("sara's organizations: %+v", mine)
	}
	if r := tn.front("GET", "/v1/organizations/"+org.ID, nil, sara); r.Status != 404 {
		t.Fatalf("outsider get: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/organizations/"+org.ID+"/members", nil, sara); r.Status != 404 {
		t.Fatalf("outsider members: %d %s", r.Status, r.Raw)
	}

	// The same name again gets a different slug, and a taken slug asked
	// for by name is refused.
	second := createOrg(t, tn, hana, "Merchant A")
	if second.Slug == org.Slug || !strings.HasPrefix(second.Slug, "merchant-a-") {
		t.Fatalf("second slug: %q", second.Slug)
	}
	if r := tn.front("POST", "/v1/organizations", obj{"name": "Other", "slug": "merchant-a"}, hana); r.code() != "slug_taken" {
		t.Fatalf("taken slug: %d %s", r.Status, r.Raw)
	}

	// The backend sees every organization.
	var all []orgData
	tn.back("GET", "/v1/admin/organizations", nil).data(&all)
	if len(all) != 2 {
		t.Fatalf("all organizations: %+v", all)
	}
	// Without a session the frontend door answers "sign in".
	if r := tn.front("GET", "/v1/organizations", nil, ""); r.Status != 401 {
		t.Fatalf("no session: %d %s", r.Status, r.Raw)
	}
}

func TestOrganizationCreationPolicies(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	hanaID, hana := tn.user("hana@example.com", "some-password")

	setPolicy := func(policy string) {
		t.Helper()
		err := e.app.DB.Platform(context.Background(), func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `UPDATE aos.tenants SET org_creation_policy = $2 WHERE id = $1`, tn.ID, policy)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// admin_only: a person needs aos.organization.create at the root.
	setPolicy(constant.OrgCreationAdminOnly)
	if r := tn.front("POST", "/v1/organizations", obj{"name": "Nope"}, hana); r.Status != 403 {
		t.Fatalf("admin_only without permission: %d %s", r.Status, r.Raw)
	}
	tn.back("PUT", "/v1/roles", obj{"name": "Staff", "permissions": []string{constant.PermOrganizationCreate}})
	tn.back("POST", "/v1/grants", obj{"principal_id": hanaID, "role": "Staff", "resource": obj{"type": "tenant", "id": "root"}})
	createOrg(t, tn, hana, "Allowed Now")

	// application: only the backend creates, and names the owner.
	setPolicy(constant.OrgCreationApplication)
	if r := tn.front("POST", "/v1/organizations", obj{"name": "Nope"}, hana); r.Status != 403 {
		t.Fatalf("application policy: %d %s", r.Status, r.Raw)
	}
	r := tn.back("POST", "/v1/admin/organizations", obj{"name": "By App", "owner_principal_id": hanaID})
	if r.Status != 201 {
		t.Fatalf("backend create: %d %s", r.Status, r.Raw)
	}
	var org orgData
	r.data(&org)
	var members []struct {
		PrincipalID string   `json:"principal_id"`
		Roles       []string `json:"roles"`
	}
	tn.back("GET", "/v1/admin/organizations/"+org.ID+"/members", nil).data(&members)
	if len(members) != 1 || members[0].PrincipalID != hanaID || members[0].Roles[0] != constant.RoleOwner {
		t.Fatalf("owner named by the backend: %+v", members)
	}
	// A person may not name another owner.
	setPolicy(constant.OrgCreationSelfService)
	if r := tn.front("POST", "/v1/organizations", obj{"name": "X", "owner_principal_id": hanaID}, hana); r.Status != 400 {
		t.Fatalf("owner from the frontend: %d %s", r.Status, r.Raw)
	}

	// A single-tenant application has no organizations at all.
	single := e.tenant("single", func(r *request.CreateTenantRequest) { r.Kind = constant.KindSingle })
	_, s := single.user("one@example.com", "some-password")
	if r := single.front("POST", "/v1/organizations", obj{"name": "Nope"}, s); r.code() != "organizations_disabled" {
		t.Fatalf("single tenant: %d %s", r.Status, r.Raw)
	}
}

func TestInvitationOfANewPerson(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	_, hana := tn.user("hana@example.com", "some-password")
	tn.back("PUT", "/v1/roles", obj{"name": "Finance", "permissions": []string{"payment.*"}})
	org := createOrg(t, tn, hana, "Merchant A")

	r := tn.front("POST", "/v1/organizations/"+org.ID+"/invitations", obj{"email": "New@Example.com", "role": "Finance"}, hana)
	if r.Status != 201 {
		t.Fatalf("invite: %d %s", r.Status, r.Raw)
	}
	var inv struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	r.data(&inv)
	if inv.Email != "new@example.com" || inv.Role != "Finance" {
		t.Fatalf("invitation: %+v", inv)
	}
	e.deliver()
	token := e.mail.token("new@example.com")
	if token == "" {
		t.Fatal("no invitation email")
	}
	if body := e.mail.to("new@example.com")[0].Body; !strings.Contains(body, "Merchant A") || !strings.Contains(body, "Finance") {
		t.Fatalf("email body: %s", body)
	}
	// The token is stored only as a hash.
	if n := tn.count(`SELECT count(*) FROM aos.invitations WHERE token_hash = $1`, token); n != 0 {
		t.Fatal("invitation token stored in clear")
	}

	// The link shows what it is for, without a session.
	var preview struct {
		Email            string `json:"email"`
		Role             string `json:"role"`
		OrganizationName string `json:"organization_name"`
		InvitedBy        string `json:"invited_by"`
		AccountExists    bool   `json:"account_exists"`
	}
	tn.front("GET", "/v1/invitations/"+token, nil, "").data(&preview)
	if preview.Email != "new@example.com" || preview.OrganizationName != "Merchant A" || preview.AccountExists || preview.InvitedBy != "hana@example.com" {
		t.Fatalf("preview: %+v", preview)
	}
	if r := tn.front("GET", "/v1/invitations/wrong-token", nil, ""); r.Status != 400 && r.Status != 401 && r.Status != 404 {
		t.Fatalf("unknown token: %d %s", r.Status, r.Raw)
	}

	// A weak password is refused; then the account is made, verified, and in.
	if r := tn.front("POST", "/v1/invitations/sign-up", obj{"token": token, "password": "password"}, ""); r.Status != 400 {
		t.Fatalf("weak password: %d %s", r.Status, r.Raw)
	}
	r = tn.front("POST", "/v1/invitations/sign-up", obj{"token": token, "password": "a-long-enough-password", "name": "New Person"}, "")
	if r.Status != 200 {
		t.Fatalf("sign up by invitation: %d %s", r.Status, r.Raw)
	}
	var signedIn authData
	r.data(&signedIn)
	if !signedIn.User.EmailVerified || signedIn.SessionToken == "" {
		t.Fatalf("signed in: %+v", signedIn)
	}
	var mine []orgData
	tn.front("GET", "/v1/organizations", nil, signedIn.SessionToken).data(&mine)
	if len(mine) != 1 || mine[0].ID != org.ID {
		t.Fatalf("new person's organizations: %+v", mine)
	}
	if ok, _ := can(t, tn, signedIn.User.ID, "payment.refund", "organization", org.Slug); !ok {
		t.Fatal("the invited role does not hold")
	}
	// Used once.
	if r := tn.front("POST", "/v1/invitations/sign-up", obj{"token": token, "password": "a-long-enough-password"}, ""); r.Status == 200 {
		t.Fatal("invitation accepted twice")
	}
	if n := tn.count(`SELECT count(*) FROM aos.grants WHERE source = $1`, constant.GrantSourceInvite); n != 1 {
		t.Fatalf("grants from invitations: %d", n)
	}
	if n := tn.count(`SELECT count(*) FROM aos.audit_log WHERE action IN ('invitation.created', 'invitation.accepted', 'user.created')`); n < 3 {
		t.Fatalf("audit entries: %d", n)
	}
}

func TestInvitationOfAnExistingPerson(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	_, hana := tn.user("hana@example.com", "some-password")
	saraID, sara := tn.user("sara@example.com", "some-password")
	_, mallory := tn.user("mallory@example.com", "some-password")
	tn.back("PUT", "/v1/roles", obj{"name": "Finance", "permissions": []string{"payment.*"}})
	org := createOrg(t, tn, hana, "Merchant A")

	invite := func() string {
		t.Helper()
		r := tn.front("POST", "/v1/organizations/"+org.ID+"/invitations", obj{"email": "sara@example.com", "role": "Finance"}, hana)
		if r.Status != 201 {
			t.Fatalf("invite: %d %s", r.Status, r.Raw)
		}
		e.deliver()
		return e.mail.token("sara@example.com")
	}
	token := invite()

	// The preview says an account exists, so the screen shows sign-in.
	var preview struct {
		AccountExists bool `json:"account_exists"`
	}
	tn.front("GET", "/v1/invitations/"+token, nil, "").data(&preview)
	if !preview.AccountExists {
		t.Fatal("preview should say the account exists")
	}
	// Sign-up with an address that has an account is refused.
	if r := tn.front("POST", "/v1/invitations/sign-up", obj{"token": token, "password": "a-long-enough-password"}, ""); r.code() != "account_exists" {
		t.Fatalf("sign up with existing account: %d %s", r.Status, r.Raw)
	}
	// Someone else who got the link cannot use it.
	if r := tn.front("POST", "/v1/invitations/accept", obj{"token": token}, mallory); r.code() != "invitation_for_another_address" {
		t.Fatalf("forwarded link: %d %s", r.Status, r.Raw)
	}
	// Without a session, accepting is not possible.
	if r := tn.front("POST", "/v1/invitations/accept", obj{"token": token}, ""); r.Status != 401 {
		t.Fatalf("accept without session: %d %s", r.Status, r.Raw)
	}
	r := tn.front("POST", "/v1/invitations/accept", obj{"token": token}, sara)
	if r.Status != 200 {
		t.Fatalf("accept: %d %s", r.Status, r.Raw)
	}
	var joined orgData
	r.data(&joined)
	if joined.ID != org.ID {
		t.Fatalf("joined: %+v", joined)
	}
	if ok, _ := can(t, tn, saraID, "payment.read", "organization", org.Slug); !ok {
		t.Fatal("sara should hold Finance")
	}
	// Sara's session now works in the organization.
	var session struct {
		Session struct {
			ActiveOrganizationID string `json:"active_organization_id"`
		} `json:"session"`
	}
	tn.front("GET", "/v1/session", nil, sara).data(&session)
	if session.Session.ActiveOrganizationID != org.ID {
		t.Fatal("accepting should switch the session to the organization")
	}

	// A member needs a role change, not another invitation.
	if r := tn.front("POST", "/v1/organizations/"+org.ID+"/invitations", obj{"email": "sara@example.com", "role": "Finance"}, hana); r.code() != "already_member" {
		t.Fatalf("invite a member: %d %s", r.Status, r.Raw)
	}

	// Decline and revoke each end an invitation. A new invitation replaces
	// a pending one for the same address.
	_, dan := tn.user("dan@example.com", "some-password")
	_ = dan
	inviteDan := func() (id, token string) {
		t.Helper()
		r := tn.front("POST", "/v1/organizations/"+org.ID+"/invitations", obj{"email": "dan@example.com", "role": "Finance"}, hana)
		if r.Status != 201 {
			t.Fatalf("invite dan: %d %s", r.Status, r.Raw)
		}
		var inv struct {
			ID string `json:"id"`
		}
		r.data(&inv)
		e.deliver()
		return inv.ID, e.mail.token("dan@example.com")
	}
	_, first := inviteDan()
	id2, second := inviteDan()
	if r := tn.front("GET", "/v1/invitations/"+first, nil, ""); r.Status == 200 {
		t.Fatal("replaced invitation still works")
	}
	var pending []struct {
		ID string `json:"id"`
	}
	tn.front("GET", "/v1/organizations/"+org.ID+"/invitations", nil, hana).data(&pending)
	if len(pending) != 1 || pending[0].ID != id2 {
		t.Fatalf("pending invitations: %+v", pending)
	}
	if r := tn.front("POST", "/v1/invitations/decline", obj{"token": second}, ""); r.Status != 200 {
		t.Fatalf("decline: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("POST", "/v1/invitations/accept", obj{"token": second}, dan); r.Status == 200 {
		t.Fatal("declined invitation accepted")
	}
	id3, third := inviteDan()
	if r := tn.front("DELETE", "/v1/organizations/"+org.ID+"/invitations/"+id3, nil, hana); r.Status != 200 {
		t.Fatalf("revoke: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/invitations/"+third, nil, ""); r.Status == 200 {
		t.Fatal("revoked invitation still works")
	}
	// Expiry.
	_, fourth := inviteDan()
	e.clock.advance(constant.InvitationTTL + 1)
	if r := tn.front("GET", "/v1/invitations/"+fourth, nil, ""); r.Status == 200 {
		t.Fatal("expired invitation still works")
	}
}

func TestNobodyGivesMoreThanTheyHold(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	_, hana := tn.user("hana@example.com", "some-password")
	saraID, sara := tn.user("sara@example.com", "some-password")
	tn.back("PUT", "/v1/roles", obj{"name": "Finance", "permissions": []string{"payment.*", constant.PermMemberInvite, constant.PermGrantManage}})
	tn.back("PUT", "/v1/roles", obj{"name": "Cashier", "permissions": []string{"payment.read"}})
	tn.back("PUT", "/v1/roles", obj{"name": "Support", "permissions": []string{"ticket.*"}})
	org := createOrg(t, tn, hana, "Merchant A")
	tn.back("POST", "/v1/grants", obj{"principal_id": saraID, "role": "Finance", "resource": obj{"type": "organization", "id": org.Slug}})

	invite := func(session, email, role string) result {
		return tn.front("POST", "/v1/organizations/"+org.ID+"/invitations", obj{"email": email, "role": role}, session)
	}
	// Sara holds payment.* and may invite, so she can hand out Cashier
	// and Finance, but not Owner and not Support.
	if r := invite(sara, "a@example.com", "Cashier"); r.Status != 201 {
		t.Fatalf("finance invites cashier: %d %s", r.Status, r.Raw)
	}
	if r := invite(sara, "b@example.com", "Finance"); r.Status != 201 {
		t.Fatalf("finance invites finance: %d %s", r.Status, r.Raw)
	}
	if r := invite(sara, "c@example.com", constant.RoleOwner); r.code() != "cannot_grant_more_than_held" {
		t.Fatalf("finance invites owner: %d %s", r.Status, r.Raw)
	}
	if r := invite(sara, "d@example.com", "Support"); r.code() != "cannot_grant_more_than_held" {
		t.Fatalf("finance invites support: %d %s", r.Status, r.Raw)
	}
	// The owner may hand out anything. The backend too.
	if r := invite(hana, "e@example.com", "Support"); r.Status != 201 {
		t.Fatalf("owner invites support: %d %s", r.Status, r.Raw)
	}
	if r := tn.back("POST", "/v1/admin/organizations/"+org.ID+"/invitations", obj{"email": "f@example.com", "role": constant.RoleOwner}); r.Status != 201 {
		t.Fatalf("backend invites owner: %d %s", r.Status, r.Raw)
	}
	// A person without aos.member.invite may not invite at all.
	tn.back("PUT", "/v1/roles", obj{"name": "Viewer", "permissions": []string{"payment.read"}})
	_, viewer := tn.user("viewer@example.com", "some-password")
	viewerID := userID(t, tn, "viewer@example.com")
	tn.back("POST", "/v1/grants", obj{"principal_id": viewerID, "role": "Viewer", "resource": obj{"type": "organization", "id": org.Slug}})
	if r := invite(viewer, "g@example.com", "Viewer"); r.Status != 403 {
		t.Fatalf("viewer invites: %d %s", r.Status, r.Raw)
	}
	// Unknown role.
	if r := invite(hana, "h@example.com", "Nonexistent"); r.Status != 400 {
		t.Fatalf("unknown role: %d %s", r.Status, r.Raw)
	}
}

func TestMembersRolesAndTheLastOwner(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	hanaID, hana := tn.user("hana@example.com", "some-password")
	saraID, sara := tn.user("sara@example.com", "some-password")
	tn.back("PUT", "/v1/roles", obj{"name": "Finance", "permissions": []string{"payment.*"}})
	org := createOrg(t, tn, hana, "Merchant A")
	tn.back("POST", "/v1/grants", obj{"principal_id": saraID, "role": "Finance", "resource": obj{"type": "organization", "id": org.Slug}})

	roleOf := func(principal string) string {
		t.Helper()
		var members []struct {
			PrincipalID string   `json:"principal_id"`
			Roles       []string `json:"roles"`
		}
		tn.back("GET", "/v1/admin/organizations/"+org.ID+"/members", nil).data(&members)
		for _, m := range members {
			if m.PrincipalID == principal {
				return strings.Join(m.Roles, ",")
			}
		}
		return ""
	}
	path := "/v1/organizations/" + org.ID + "/members/"

	// The last owner cannot step down or leave.
	if r := tn.front("PUT", path+hanaID+"/role", obj{"role": "Finance"}, hana); r.code() != "last_owner" {
		t.Fatalf("last owner steps down: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("DELETE", path+hanaID, nil, hana); r.code() != "last_owner" {
		t.Fatalf("last owner leaves: %d %s", r.Status, r.Raw)
	}
	// Sara, with Finance only, may not change roles or remove people.
	if r := tn.front("PUT", path+hanaID+"/role", obj{"role": "Finance"}, sara); r.Status != 403 {
		t.Fatalf("finance changes a role: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("DELETE", path+hanaID, nil, sara); r.Status != 403 {
		t.Fatalf("finance removes the owner: %d %s", r.Status, r.Raw)
	}
	// Hana makes Sara an owner, then steps down to Finance.
	if r := tn.front("PUT", path+saraID+"/role", obj{"role": constant.RoleOwner}, hana); r.Status != 200 {
		t.Fatalf("promote sara: %d %s", r.Status, r.Raw)
	}
	if got := roleOf(saraID); got != constant.RoleOwner {
		t.Fatalf("sara's role: %q", got)
	}
	if r := tn.front("PUT", path+hanaID+"/role", obj{"role": "Finance"}, hana); r.Status != 200 {
		t.Fatalf("hana steps down: %d %s", r.Status, r.Raw)
	}
	if got := roleOf(hanaID); got != "Finance" {
		t.Fatalf("hana's role: %q", got)
	}
	// Now Hana may leave by herself. She is gone from the organization
	// and her session no longer works in it.
	if r := tn.front("DELETE", path+hanaID, nil, hana); r.Status != 200 {
		t.Fatalf("hana leaves: %d %s", r.Status, r.Raw)
	}
	if got := roleOf(hanaID); got != "" {
		t.Fatalf("hana still a member with %q", got)
	}
	if ok, _ := can(t, tn, hanaID, "payment.read", "organization", org.Slug); ok {
		t.Fatal("hana still holds a permission in the organization")
	}
	var session struct {
		Session struct {
			ActiveOrganizationID string `json:"active_organization_id"`
		} `json:"session"`
	}
	tn.front("GET", "/v1/session", nil, hana).data(&session)
	if session.Session.ActiveOrganizationID != "" {
		t.Fatal("session still active in the organization she left")
	}
	// An unknown member.
	if r := tn.front("DELETE", path+hanaID, nil, sara); r.Status != 404 {
		t.Fatalf("remove a non-member: %d %s", r.Status, r.Raw)
	}
	// Removing a person from the organization removes their grants
	// beneath it too.
	tn.back("PUT", "/v1/resources", obj{"type": "branch", "id": "b1", "parent": obj{"type": "organization", "id": org.Slug}})
	danID, _ := tn.user("dan@example.com", "some-password")
	tn.back("POST", "/v1/grants", obj{"principal_id": danID, "role": "Finance", "resource": obj{"type": "branch", "id": "b1"}})
	if got := roleOf(danID); got != "Finance" {
		t.Fatalf("dan via branch: %q", got)
	}
	if r := tn.front("DELETE", path+danID, nil, sara); r.Status != 200 {
		t.Fatalf("remove dan: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.grants WHERE principal_id = $1`, danID); n != 0 {
		t.Fatalf("dan's grants left: %d", n)
	}
}

func TestSwitchAndDeleteOrganization(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	_, hana := tn.user("hana@example.com", "some-password")
	saraID, sara := tn.user("sara@example.com", "some-password")
	tn.back("PUT", "/v1/roles", obj{"name": "Finance", "permissions": []string{"payment.*"}})
	a := createOrg(t, tn, hana, "Merchant A")
	b := createOrg(t, tn, hana, "Merchant B")
	tn.back("POST", "/v1/grants", obj{"principal_id": saraID, "role": "Finance", "resource": obj{"type": "organization", "id": a.Slug}})

	active := func(session string) string {
		t.Helper()
		var s struct {
			Session struct {
				ActiveOrganizationID string `json:"active_organization_id"`
			} `json:"session"`
		}
		tn.front("GET", "/v1/session", nil, session).data(&s)
		return s.Session.ActiveOrganizationID
	}
	if active(hana) != b.ID {
		t.Fatal("the newest organization should be active")
	}
	if r := tn.front("POST", "/v1/organizations/"+a.ID+"/switch", nil, hana); r.Status != 200 {
		t.Fatalf("switch: %d %s", r.Status, r.Raw)
	}
	if active(hana) != a.ID {
		t.Fatal("switch did not take")
	}
	// Sara cannot switch into an organization she is not in.
	if r := tn.front("POST", "/v1/organizations/"+b.ID+"/switch", nil, sara); r.Status != 404 {
		t.Fatalf("switch into a foreign organization: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("POST", "/v1/organizations/"+a.ID+"/switch", nil, sara); r.Status != 200 {
		t.Fatalf("sara switches: %d %s", r.Status, r.Raw)
	}

	// Only someone with aos.organization.manage (the owner) deletes.
	if r := tn.front("DELETE", "/v1/organizations/"+a.ID, nil, sara); r.Status != 403 {
		t.Fatalf("finance deletes: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("DELETE", "/v1/organizations/"+a.ID, nil, hana); r.Status != 200 {
		t.Fatalf("owner deletes: %d %s", r.Status, r.Raw)
	}
	// Gone from every list, nobody holds anything in it, sessions moved out.
	var mine []orgData
	tn.front("GET", "/v1/organizations", nil, hana).data(&mine)
	if len(mine) != 1 || mine[0].ID != b.ID {
		t.Fatalf("after delete: %+v", mine)
	}
	if r := tn.front("GET", "/v1/organizations/"+a.ID, nil, hana); r.Status != 404 {
		t.Fatalf("deleted organization still answers: %d", r.Status)
	}
	if ok, _ := can(t, tn, saraID, "payment.read", "organization", a.Slug); ok {
		t.Fatal("a grant survived the deletion")
	}
	if active(hana) != "" || active(sara) != "" {
		t.Fatal("sessions still point at the deleted organization")
	}
	if n := tn.count(`SELECT count(*) FROM aos.organizations WHERE status = 'deleted' AND purge_after IS NOT NULL`); n != 1 {
		t.Fatalf("soft-deleted organizations: %d", n)
	}
	if n := tn.count(`SELECT count(*) FROM aos.audit_log WHERE action = 'organization.deleted'`); n != 1 {
		t.Fatalf("audit of the deletion: %d", n)
	}
}

func TestBackendDoorRefusesSecretKeyFromBrowsers(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	if r := tn.back("GET", "/v1/admin/organizations", nil, "Origin", "https://app.test"); r.Status != 403 {
		t.Fatalf("secret key with an Origin: %d %s", r.Status, r.Raw)
	}
	// And the frontend door refuses the secret key outright.
	if r := e.call("GET", "/v1/organizations", nil, constant.HeaderPublishableKey, tn.SK); r.Status != 401 {
		t.Fatalf("secret key at the frontend door: %d %s", r.Status, r.Raw)
	}
}
