package request

import "github.com/flash-software-technology/aos/internal/constant/errors"

// CreateUserRequest is an admin creating an account. The person receives
// a setup link and chooses their own password. No password is ever set
// or seen by the admin.
type CreateUserRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	// Role and Resource, when given, grant that role there at creation.
	Role     string       `json:"role"`
	Resource *ResourceRef `json:"resource"`
}

func (r *CreateUserRequest) Validate() error {
	r.Email = NormalizeEmail(r.Email)
	f := fields{}
	if !validEmail(r.Email) {
		f["email"] = "must be a valid email address"
	}
	if len(r.Name) > 200 {
		f["name"] = "must be at most 200 characters"
	}
	if (r.Role == "") != (r.Resource == nil) {
		f["role"] = "role and resource go together"
	}
	if r.Resource != nil {
		r.Resource.check("resource", f)
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type SuspendUserRequest struct {
	Reason string `json:"reason"`
}

func (r *SuspendUserRequest) Validate() error {
	f := fields{}
	f.require("reason", r.Reason)
	if len(r.Reason) > 500 {
		f["reason"] = "must be at most 500 characters"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// ListUsersRequest pages through users. Cursor is opaque to the caller.
type ListUsersRequest struct {
	Cursor string
	Limit  int
}
