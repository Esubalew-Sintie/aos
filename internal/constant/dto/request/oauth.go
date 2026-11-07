package request

import (
	"net/url"
	"strings"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/errors"
)

// PutOAuthClientRequest registers another application as a client of
// this tenant (MACH-5), or a machine that proves itself with a secret.
type PutOAuthClientRequest struct {
	// ClientID is chosen by the developer, or made when empty.
	ClientID     string   `json:"client_id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Kind         string   `json:"kind"` // confidential (the default) or public
	RedirectURIs []string `json:"redirect_uris"`
	// AllowedScopes are the permission names the client may ask for, on
	// top of openid, profile, email and offline_access.
	AllowedScopes []string `json:"allowed_scopes"`
	GrantTypes    []string `json:"grant_types"`
	// ServicePrincipalID is the service account or agent a confidential
	// client acts as with client credentials or token exchange.
	ServicePrincipalID string `json:"service_principal_id"`
	// RotateSecret makes a new secret for an existing confidential client.
	RotateSecret bool `json:"rotate_secret"`
}

func (r *PutOAuthClientRequest) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	r.ClientID = strings.TrimSpace(r.ClientID)
	if r.Kind == "" {
		r.Kind = constant.ClientConfidential
	}
	if len(r.GrantTypes) == 0 {
		r.GrantTypes = []string{constant.GrantAuthorizationCode, constant.GrantRefreshToken}
	}
	f := fields{}
	f.require("name", r.Name)
	if r.ClientID != "" && (len(r.ClientID) > 100 || strings.ContainsAny(r.ClientID, " \t\n")) {
		f["client_id"] = "must be a short identifier without spaces"
	}
	if r.Kind != constant.ClientConfidential && r.Kind != constant.ClientPublic {
		f["kind"] = "must be confidential or public"
	}
	for _, u := range r.RedirectURIs {
		p, err := url.Parse(u)
		if err != nil || p.Scheme == "" || p.Host == "" && p.Scheme != "http" || p.Fragment != "" {
			f["redirect_uris"] = "each must be an exact address such as https://app.example.com/callback"
			break
		}
	}
	for _, s := range r.AllowedScopes {
		if !validPermissionPattern(s) {
			f["allowed_scopes"] = "each must be a permission name or a prefix such as payment.*"
			break
		}
	}
	for _, g := range r.GrantTypes {
		switch g {
		case constant.GrantAuthorizationCode, constant.GrantRefreshToken, constant.GrantClientCredentials, constant.GrantDeviceCode, constant.GrantTokenExchange:
		default:
			f["grant_types"] = "holds an unknown grant type"
		}
	}
	if r.ServicePrincipalID != "" && !validUUID(r.ServicePrincipalID) {
		f["service_principal_id"] = "must be an id"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// ConsentRequest is the person's answer to an authorization request.
type ConsentRequest struct {
	RequestID string `json:"request_id"`
	Approve   bool   `json:"approve"`
}

func (r *ConsentRequest) Validate() error {
	if !validUUID(r.RequestID) {
		return errors.Validation(map[string]string{"request_id": "must be an id"})
	}
	return nil
}

// DeviceApproveRequest is the person typing the code a device showed.
type DeviceApproveRequest struct {
	UserCode string `json:"user_code"`
	Approve  bool   `json:"approve"`
}

func (r *DeviceApproveRequest) Validate() error {
	r.UserCode = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(r.UserCode), "-", ""), " ", ""))
	if len(r.UserCode) != 8 {
		return errors.Validation(map[string]string{"user_code": "must be the 8 characters the device shows"})
	}
	return nil
}
