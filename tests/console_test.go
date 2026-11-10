package tests

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// These are the read routes a developer console uses: the audit log and
// the grants of a principal or on a resource.

type auditPage struct {
	Entries []struct {
		Seq        int64     `json:"seq"`
		OccurredAt time.Time `json:"occurred_at"`
		Action     string    `json:"action"`
		Result     string    `json:"result"`
		ActorType  string    `json:"actor_type"`
		ActorID    string    `json:"actor_id"`
		ActorEmail string    `json:"actor_email"`
		TargetType string    `json:"target_type"`
		TargetID   string    `json:"target_id"`
	} `json:"entries"`
	NextBefore int64 `json:"next_before"`
}

func (tn *tenant) auditPage(query string) auditPage {
	tn.e.t.Helper()
	r := tn.back("GET", "/v1/audit"+query, nil)
	if r.Status != 200 {
		tn.e.t.Fatalf("GET /v1/audit%s: %d %s", query, r.Status, r.Raw)
	}
	var page auditPage
	r.data(&page)
	return page
}

func TestAuditLogListsNewestFirstAndFilters(t *testing.T) {
	_, tn := busyTenant(t)
	hana, _ := tn.signInSession("hana@example.com", "right-password")

	page := tn.auditPage("")
	if len(page.Entries) < 6 {
		t.Fatalf("want at least 6 entries, got %d", len(page.Entries))
	}
	if page.NextBefore != 0 {
		t.Fatalf("a short log has no next page, got next_before %d", page.NextBefore)
	}
	for i := 1; i < len(page.Entries); i++ {
		if page.Entries[i].Seq >= page.Entries[i-1].Seq {
			t.Fatalf("entries are not newest first: %d after %d", page.Entries[i].Seq, page.Entries[i-1].Seq)
		}
	}
	if last := page.Entries[len(page.Entries)-1]; last.Action != "tenant.created" || last.ActorType != "system" {
		t.Fatalf("the oldest entry should be the tenant's creation by the system, got %+v", last)
	}

	// Filter by action prefix.
	signins := tn.auditPage("?action=signin.")
	if len(signins.Entries) < 2 {
		t.Fatalf("want the sign-in entries, got %d", len(signins.Entries))
	}
	for _, en := range signins.Entries {
		if !strings.HasPrefix(en.Action, "signin.") {
			t.Fatalf("action filter let %q through", en.Action)
		}
	}

	// Filter by actor. A user's entries carry their email.
	mine := tn.auditPage("?actor_id=" + hana)
	if len(mine.Entries) == 0 {
		t.Fatal("no entries for the user who signed in")
	}
	for _, en := range mine.Entries {
		if en.ActorID != hana || en.ActorType != "user" || en.ActorEmail != "hana@example.com" {
			t.Fatalf("actor filter returned %+v", en)
		}
	}
	if got := tn.auditPage("?actor_id=" + hana + "&action=signin.succeeded"); len(got.Entries) == 0 {
		t.Fatal("filters do not combine")
	}

	// Filter by target.
	if got := tn.auditPage("?target_id=" + hana); len(got.Entries) == 0 {
		t.Fatal("no entries about the user as a target")
	} else {
		for _, en := range got.Entries {
			if en.TargetID != hana {
				t.Fatalf("target filter returned %+v", en)
			}
		}
	}

	// Bad filters are refused.
	for _, q := range []string{"?actor_id=not-an-id", "?before=abc", "?before=-3"} {
		if r := tn.back("GET", "/v1/audit"+q, nil); r.Status != 400 || r.Body.Error == nil || r.Body.Error.Type != "validation" {
			t.Fatalf("GET /v1/audit%s: want a validation error, got %d %s", q, r.Status, r.Raw)
		}
	}

	// The route is for the backend only.
	if r := tn.front("GET", "/v1/audit", nil, ""); r.Status == 200 {
		t.Fatal("the audit log was readable with the publishable key")
	}
}

func TestAuditLogPages(t *testing.T) {
	_, tn := busyTenant(t)
	all := tn.auditPage("?limit=200")
	if len(all.Entries) < 5 {
		t.Fatalf("want at least 5 entries, got %d", len(all.Entries))
	}

	var seen []int64
	query := "?limit=2"
	for pages := 0; ; pages++ {
		if pages > 100 {
			t.Fatal("paging does not end")
		}
		page := tn.auditPage(query)
		if len(page.Entries) > 2 {
			t.Fatalf("limit 2 returned %d entries", len(page.Entries))
		}
		for _, en := range page.Entries {
			seen = append(seen, en.Seq)
		}
		if page.NextBefore == 0 {
			break
		}
		if page.NextBefore != page.Entries[len(page.Entries)-1].Seq {
			t.Fatalf("next_before %d is not the last entry's seq", page.NextBefore)
		}
		query = fmt.Sprintf("?limit=2&before=%d", page.NextBefore)
	}
	if len(seen) != len(all.Entries) {
		t.Fatalf("paging saw %d entries, the whole log has %d", len(seen), len(all.Entries))
	}
	for i, seq := range seen {
		if seq != all.Entries[i].Seq {
			t.Fatalf("entry %d: paging gave seq %d, the whole log %d", i, seq, all.Entries[i].Seq)
		}
	}

	// A limit over the cap is held to it, and still answers.
	if r := tn.back("GET", "/v1/audit?limit=100000", nil); r.Status != 200 {
		t.Fatalf("a large limit: %d %s", r.Status, r.Raw)
	}
}

func TestAuditLogIsTenantIsolated(t *testing.T) {
	e, a := busyTenant(t)
	hana, _ := a.signInSession("hana@example.com", "right-password")
	b := e.tenant("other")

	page := b.auditPage("?limit=200")
	for _, en := range page.Entries {
		if en.ActorID == hana || en.TargetID == hana {
			t.Fatalf("tenant b sees tenant a's entry %+v", en)
		}
	}
	if got := b.auditPage("?actor_id=" + hana); len(got.Entries) != 0 {
		t.Fatalf("tenant b sees %d entries of tenant a's user", len(got.Entries))
	}
	if len(page.Entries) >= len(a.auditPage("?limit=200").Entries) {
		t.Fatal("a fresh tenant should have a shorter log than a busy one")
	}
}

type grantRecord struct {
	ID          string `json:"id"`
	PrincipalID string `json:"principal_id"`
	Role        string `json:"role"`
	Resource    struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"resource"`
	Effect    string     `json:"effect"`
	ExpiresAt *time.Time `json:"expires_at"`
	Reason    string     `json:"reason"`
	Source    string     `json:"source"`
	CreatedAt time.Time  `json:"created_at"`
}

func (tn *tenant) grants(query string) []grantRecord {
	tn.e.t.Helper()
	r := tn.back("GET", "/v1/grants"+query, nil)
	if r.Status != 200 {
		tn.e.t.Fatalf("GET /v1/grants%s: %d %s", query, r.Status, r.Raw)
	}
	var out []grantRecord
	r.data(&out)
	return out
}

func TestGrantsListByPrincipalAndResource(t *testing.T) {
	w := newWorld(t)
	until := w.e.clock.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	w.grant(w.daniel, "Refunds", "branch", "branch-1", "allow", obj{"expires_at": until, "reason": "covering for sara"})

	sara := w.tn.grants("?principal_id=" + w.sara)
	if len(sara) != 2 {
		t.Fatalf("sara holds 2 grants, got %d: %+v", len(sara), sara)
	}
	byRole := map[string]grantRecord{}
	for _, g := range sara {
		if g.PrincipalID != w.sara || g.ID == "" || g.CreatedAt.IsZero() || g.Source == "" {
			t.Fatalf("incomplete grant %+v", g)
		}
		byRole[g.Role] = g
	}
	if g := byRole["Finance"]; g.Effect != "allow" || g.Resource.Type != "organization" || g.Resource.ID != "merchant-a" {
		t.Fatalf("finance grant: %+v", g)
	}
	if g := byRole["Refunds"]; g.Effect != "deny" || g.Resource.Type != "branch" || g.Resource.ID != "branch-2" {
		t.Fatalf("refunds deny: %+v", g)
	}

	daniel := w.tn.grants("?principal_id=" + w.daniel)
	var temp *grantRecord
	for i := range daniel {
		if daniel[i].Role == "Refunds" {
			temp = &daniel[i]
		}
	}
	if temp == nil || temp.ExpiresAt == nil || !temp.ExpiresAt.Equal(until) || temp.Reason != "covering for sara" {
		t.Fatalf("the temporary grant lost its expiry or reason: %+v", temp)
	}

	branch1 := w.tn.grants("?resource_type=branch&resource_id=branch-1")
	if len(branch1) != 2 {
		t.Fatalf("branch-1 has 2 grants, got %d", len(branch1))
	}
	for _, g := range branch1 {
		if g.PrincipalID != w.daniel || g.Resource.ID != "branch-1" {
			t.Fatalf("resource filter returned %+v", g)
		}
	}
	// Both filters together narrow further.
	if got := w.tn.grants("?principal_id=" + w.sara + "&resource_type=branch&resource_id=branch-1"); len(got) != 0 {
		t.Fatalf("sara has nothing on branch-1, got %+v", got)
	}
	if got := w.tn.grants("?principal_id=" + w.sara + "&limit=1"); len(got) != 1 {
		t.Fatalf("limit 1 returned %d", len(got))
	}
	if got := w.tn.grants("?resource_type=branch&resource_id=nope"); len(got) != 0 {
		t.Fatalf("an unknown resource has no grants, got %d", len(got))
	}
}

func TestGrantsListNeedsAFilter(t *testing.T) {
	w := newWorld(t)
	for _, q := range []string{"", "?limit=10", "?resource_type=branch", "?resource_id=branch-1", "?principal_id=not-an-id"} {
		r := w.tn.back("GET", "/v1/grants"+q, nil)
		if r.Status != 400 || r.Body.Error == nil || r.Body.Error.Type != "validation" {
			t.Fatalf("GET /v1/grants%s: want a validation error, got %d %s", q, r.Status, r.Raw)
		}
	}
	if r := w.tn.front("GET", "/v1/grants?principal_id="+w.sara, nil, ""); r.Status == 200 {
		t.Fatal("grants were readable with the publishable key")
	}
}

func TestGrantsListIsTenantIsolated(t *testing.T) {
	w := newWorld(t)
	other := w.e.tenant("other")
	if got := other.grants("?principal_id=" + w.sara); len(got) != 0 {
		t.Fatalf("another tenant sees %d of sara's grants", len(got))
	}
	other.back("PUT", "/v1/resources", obj{"type": "organization", "id": "merchant-a"})
	if got := other.grants("?resource_type=organization&resource_id=merchant-a"); len(got) != 0 {
		t.Fatalf("another tenant sees %d grants on its own merchant-a", len(got))
	}
}
