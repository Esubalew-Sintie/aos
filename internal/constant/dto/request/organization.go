package request

import (
	"regexp"
	"strings"

	"github.com/flash-softeware/aos/internal/constant/errors"
)

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify turns a name into a short name: lower case, letters, digits
// and hyphens.
func Slugify(name string) string {
	s := nonSlug.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	s = strings.Trim(s, "-")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	return s
}

type CreateOrganizationRequest struct {
	Name string `json:"name"`
	// Slug is optional. It is made from the name when empty.
	Slug string `json:"slug"`
	// OwnerPrincipalID names the first owner when the backend creates the
	// organization. A signed-in creator is the owner by default.
	OwnerPrincipalID string `json:"owner_principal_id"`
}

func (r *CreateOrganizationRequest) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Slug == "" {
		r.Slug = Slugify(r.Name)
	}
	f := fields{}
	f.require("name", r.Name)
	if len(r.Name) > 200 {
		f["name"] = "must be at most 200 characters"
	}
	if !slugPattern.MatchString(r.Slug) {
		f["slug"] = "must be 2 to 63 lower-case letters, digits or hyphens"
	}
	if r.OwnerPrincipalID != "" && !validUUID(r.OwnerPrincipalID) {
		f["owner_principal_id"] = "must be an id"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type InviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	// Resource narrows the invitation to one place inside the
	// organization, such as a branch. Empty means the whole organization.
	Resource *ResourceRef `json:"resource"`
}

func (r *InviteRequest) Validate() error {
	r.Email = NormalizeEmail(r.Email)
	f := fields{}
	if !validEmail(r.Email) {
		f["email"] = "must be a valid email address"
	}
	f.require("role", r.Role)
	if r.Resource != nil {
		r.Resource.check("resource", f)
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type ChangeMemberRoleRequest struct {
	Role string `json:"role"`
}

func (r *ChangeMemberRoleRequest) Validate() error {
	f := fields{}
	f.require("role", r.Role)
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type InvitationTokenRequest struct {
	Token string `json:"token"`
}

func (r *InvitationTokenRequest) Validate() error {
	f := fields{}
	f.require("token", r.Token)
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// InvitationSignUpRequest creates an account for a person with no
// account, from an invitation. The address comes from the invitation.
type InvitationSignUpRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func (r *InvitationSignUpRequest) Validate() error {
	f := fields{}
	f.require("token", r.Token)
	if p := passwordProblem(r.Password); p != "" {
		f["password"] = p
	}
	if len(r.Name) > 200 {
		f["name"] = "must be at most 200 characters"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}
