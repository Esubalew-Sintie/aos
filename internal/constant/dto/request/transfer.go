package request

import (
	"strings"

	"github.com/flash-softeware/aos/internal/constant/errors"
)

// ImportUser is one account moved from another system. PasswordHash may
// be Argon2id, bcrypt, scrypt or PBKDF2; it is replaced by Argon2id the
// first time the person signs in.
type ImportUser struct {
	Email         string       `json:"email"`
	Name          string       `json:"name"`
	EmailVerified bool         `json:"email_verified"`
	PasswordHash  string       `json:"password_hash"`
	Roles         []ImportRole `json:"roles"`
}

type ImportRole struct {
	Role     string      `json:"role"`
	Resource ResourceRef `json:"resource"`
}

type ImportUsersRequest struct {
	Users []ImportUser `json:"users"`
}

func (r *ImportUsersRequest) Validate() error {
	if len(r.Users) == 0 || len(r.Users) > 1000 {
		return errors.Validation(map[string]string{"users": "must hold 1 to 1000 users"})
	}
	for i := range r.Users {
		r.Users[i].Email = NormalizeEmail(r.Users[i].Email)
		r.Users[i].Name = strings.TrimSpace(r.Users[i].Name)
	}
	return nil
}

// ExportRequest asks for an encrypted archive of the tenant (HOST-6).
type ExportRequest struct {
	// Passphrase encrypts the archive. Keep it apart from the archive.
	Passphrase string `json:"passphrase"`
}

func (r *ExportRequest) Validate() error {
	if len(r.Passphrase) < 12 {
		return errors.Validation(map[string]string{"passphrase": "must be at least 12 characters"})
	}
	return nil
}

type ImportArchiveRequest struct {
	Archive    string `json:"archive"`
	Passphrase string `json:"passphrase"`
}

func (r *ImportArchiveRequest) Validate() error {
	f := fields{}
	f.require("archive", r.Archive)
	f.require("passphrase", r.Passphrase)
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// StartReviewRequest opens an access review of one organization (ADM-6).
type StartReviewRequest struct {
	OrganizationID string `json:"organization_id"`
	// ReviewerPrincipalID defaults to the person starting it.
	ReviewerPrincipalID string `json:"reviewer_principal_id"`
	DueDays             int    `json:"due_days"`
}

func (r *StartReviewRequest) Validate() error {
	f := fields{}
	if !validUUID(r.OrganizationID) {
		f["organization_id"] = "must be an id"
	}
	if r.ReviewerPrincipalID != "" && !validUUID(r.ReviewerPrincipalID) {
		f["reviewer_principal_id"] = "must be an id"
	}
	if r.DueDays < 0 || r.DueDays > 365 {
		f["due_days"] = "must be between 0 and 365"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type ReviewDecisionRequest struct {
	Decision string `json:"decision"` // keep or remove
}

func (r *ReviewDecisionRequest) Validate() error {
	if r.Decision != "keep" && r.Decision != "remove" {
		return errors.Validation(map[string]string{"decision": "must be keep or remove"})
	}
	return nil
}
