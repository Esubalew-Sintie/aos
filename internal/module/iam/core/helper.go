// Package core holds the decision rule of the permission check.
package core

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/model"
)

// Reason codes of a permission decision.
const (
	ReasonAllowed               = "allowed"
	ReasonNoMatchingGrant       = "no_matching_grant"
	ReasonDeniedByGrant         = "denied_by_grant"
	ReasonConditionNotSupported = "condition_not_supported"
	// ReasonConditionNotMet: an allow carries a condition and the
	// request's context does not satisfy it.
	ReasonConditionNotMet   = "condition_not_met"
	ReasonUnknownPrincipal  = "unknown_principal"
	ReasonPrincipalInactive = "principal_inactive"
	ReasonUnknownResource   = "unknown_resource"
	// ReasonStepUpRequired: the grant allows it, but the session's second
	// factor is too old or missing (SIGN-9).
	ReasonStepUpRequired = "step_up_required"
	// Scopes and agents (MACH-3, MACH-8, MACH-9).
	ReasonOutsideScope      = "outside_scope"
	ReasonNoDelegation      = "no_delegation"
	ReasonOutsideDelegation = "outside_delegation"
	ReasonApprovalRequired  = "approval_required"
	ReasonApprovalPending   = "approval_pending"
	ReasonApprovalDeclined  = "approval_declined"
	ReasonApprovalInvalid   = "approval_invalid"
	ReasonApproved          = "approved"
)

// Outcome is the result of weighing the grants that match a question.
type Outcome struct {
	Allowed bool
	Reason  string
	// Grant is the grant that decided it, when one did.
	Grant *model.MatchedGrant
}

// Decide applies the rules of the engine to the grants that match:
//
//  1. Deny beats allow. One matching deny is enough, wherever it sits in
//     the tree and whoever else allows.
//  2. Otherwise one matching allow is enough.
//  3. Otherwise the answer is deny. That is the default.
//
// Grant conditions are not evaluated yet (milestone M6), and the rule
// when unsure is to refuse. So a deny that carries a condition counts as
// a deny, and an allow that carries a condition is not counted.
//
// grants must be ordered nearest first, so the grant named in the answer
// is the one closest to the resource.
func Decide(grants []model.MatchedGrant) Outcome {
	return DecideWith(grants, nil)
}

// DecideWith is Decide with a request context for grant conditions
// (PERM-9). A deny whose condition holds, or cannot be evaluated, denies.
// An allow counts only when its condition holds. With a nil context no
// condition can hold, so a conditional allow is reported as unsupported.
func DecideWith(grants []model.MatchedGrant, env map[string]any) Outcome {
	var allow, conditional *model.MatchedGrant
	for i := range grants {
		g := &grants[i]
		holds := true
		if g.Conditional {
			if env == nil {
				holds = false
			} else {
				ok, err := EvalCondition(g.Condition, env)
				holds = err == nil && ok
			}
		}
		switch {
		case g.Effect == constant.EffectDeny:
			if g.Conditional && env != nil {
				// A deny stands unless its condition clearly does not hold.
				if ok, err := EvalCondition(g.Condition, env); err == nil && !ok {
					continue
				}
			}
			return Outcome{Allowed: false, Reason: ReasonDeniedByGrant, Grant: g}
		case g.Conditional && !holds:
			if conditional == nil {
				conditional = g
			}
		case allow == nil:
			allow = g
		}
	}
	switch {
	case allow != nil:
		return Outcome{Allowed: true, Reason: ReasonAllowed, Grant: allow}
	case conditional != nil && env != nil:
		return Outcome{Allowed: false, Reason: ReasonConditionNotMet, Grant: conditional}
	case conditional != nil:
		return Outcome{Allowed: false, Reason: ReasonConditionNotSupported, Grant: conditional}
	}
	return Outcome{Allowed: false, Reason: ReasonNoMatchingGrant}
}

// Covers reports whether an actor who holds the patterns in held may hand
// out every pattern in wanted. "*" covers anything. "payment.*" covers
// "payment.*", "payment.refund" and "payment.refund.partial". An exact
// name covers only itself.
func Covers(held, wanted []string) bool {
	for _, w := range wanted {
		if !covered(held, w) {
			return false
		}
	}
	return true
}

func covered(held []string, want string) bool {
	for _, h := range held {
		switch {
		case h == "*", h == want:
			return true
		case len(h) > 2 && h[len(h)-2:] == ".*":
			prefix := h[:len(h)-1] // "payment."
			if len(want) > len(prefix) && want[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// ActionDigest binds an approval to one exact action: the permission,
// the resource, and the values given.
func ActionDigest(permission, resourceID string, details map[string]any) []byte {
	encoded, _ := json.Marshal(details) // keys are sorted by encoding/json
	sum := sha256.Sum256([]byte(permission + "|" + resourceID + "|" + string(encoded)))
	return sum[:]
}
