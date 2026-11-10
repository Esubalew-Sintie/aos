package core

import (
	"testing"

	"github.com/flash-software-technology/aos/internal/constant/model"
)

func TestDecide(t *testing.T) {
	allow := model.MatchedGrant{ID: "allow", Effect: "allow"}
	deny := model.MatchedGrant{ID: "deny", Effect: "deny"}
	allowIf := model.MatchedGrant{ID: "allow-if", Effect: "allow", Conditional: true}
	denyIf := model.MatchedGrant{ID: "deny-if", Effect: "deny", Conditional: true}

	cases := []struct {
		name    string
		grants  []model.MatchedGrant
		allowed bool
		reason  string
		decider string
	}{
		{"nothing matches: the default is deny", nil, false, ReasonNoMatchingGrant, ""},
		{"one allow is enough", []model.MatchedGrant{allow}, true, ReasonAllowed, "allow"},
		{"deny beats allow", []model.MatchedGrant{allow, deny}, false, ReasonDeniedByGrant, "deny"},
		{"deny beats allow whatever the order", []model.MatchedGrant{deny, allow}, false, ReasonDeniedByGrant, "deny"},
		{"an allow with a condition is not counted yet", []model.MatchedGrant{allowIf}, false, ReasonConditionNotSupported, "allow-if"},
		{"a plain allow still wins beside a conditional one", []model.MatchedGrant{allowIf, allow}, true, ReasonAllowed, "allow"},
		{"a deny with a condition counts as a deny", []model.MatchedGrant{allow, denyIf}, false, ReasonDeniedByGrant, "deny-if"},
	}
	for _, c := range cases {
		got := Decide(c.grants)
		decider := ""
		if got.Grant != nil {
			decider = got.Grant.ID
		}
		if got.Allowed != c.allowed || got.Reason != c.reason || decider != c.decider {
			t.Errorf("%s: got (%v, %s, %q), want (%v, %s, %q)",
				c.name, got.Allowed, got.Reason, decider, c.allowed, c.reason, c.decider)
		}
	}
}
