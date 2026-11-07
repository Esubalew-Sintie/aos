package request

import (
	"net"
	"strings"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/errors"
)

type CreateConnectionRequest struct {
	OrganizationID string `json:"organization_id"`
	Protocol       string `json:"protocol"` // oidc (the default) or saml
	Name           string `json:"name"`
}

func (r *CreateConnectionRequest) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Protocol == "" {
		r.Protocol = constant.SSOProtocolOIDC
	}
	f := fields{}
	if !validUUID(r.OrganizationID) {
		f["organization_id"] = "must be an id"
	}
	if r.Protocol != constant.SSOProtocolOIDC && r.Protocol != constant.SSOProtocolSAML {
		f["protocol"] = "must be oidc or saml"
	}
	if len(r.Name) > 200 {
		f["name"] = "must be at most 200 characters"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// ConnectionSettingsRequest is what the IT admin pastes back from the
// identity provider.
type ConnectionSettingsRequest struct {
	Name         string `json:"name"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	// SAML (stored; sign-in with SAML is not built yet).
	SAMLEntityID    string `json:"saml_entity_id"`
	SAMLSSOURL      string `json:"saml_sso_url"`
	SAMLCertificate string `json:"saml_certificate"`
}

func (r *ConnectionSettingsRequest) Validate(protocol string) error {
	r.Issuer = strings.TrimRight(strings.TrimSpace(r.Issuer), "/")
	f := fields{}
	if protocol == constant.SSOProtocolOIDC {
		if !validOrigin(r.Issuer, true) {
			f["issuer"] = "must be the provider's address, such as https://login.example.com"
		}
		f.require("client_id", r.ClientID)
	} else {
		f.require("saml_entity_id", r.SAMLEntityID)
		if !validOrigin(r.SAMLSSOURL, true) {
			f["saml_sso_url"] = "must be an address"
		}
		f.require("saml_certificate", r.SAMLCertificate)
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type GroupMappingRequest struct {
	Group string `json:"group"`
	Role  string `json:"role"`
	// Resource narrows the role to a place inside the organization. Empty
	// means the organization itself.
	Resource *ResourceRef `json:"resource"`
}

// MappingsRequest sets how the company's groups become roles.
type MappingsRequest struct {
	Mappings             []GroupMappingRequest `json:"mappings"`
	DefaultRole          string                `json:"default_role"`
	TrustIdPSecondFactor *bool                 `json:"trust_idp_second_factor"`
}

func (r *MappingsRequest) Validate() error {
	f := fields{}
	if len(r.Mappings) > 200 {
		f["mappings"] = "holds too many entries"
	}
	for _, m := range r.Mappings {
		if strings.TrimSpace(m.Group) == "" || strings.TrimSpace(m.Role) == "" {
			f["mappings"] = "each needs a group and a role"
			break
		}
		if m.Resource != nil {
			m.Resource.check("mappings", f)
		}
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type DomainRequest struct {
	Domain string `json:"domain"`
}

func (r *DomainRequest) Validate() error {
	r.Domain = strings.ToLower(strings.TrimSpace(r.Domain))
	if r.Domain == "" || len(r.Domain) > 253 || strings.Contains(r.Domain, "/") || strings.Contains(r.Domain, "@") || !strings.Contains(r.Domain, ".") {
		return errors.Validation(map[string]string{"domain": "must be a domain such as bank.example"})
	}
	return nil
}

type SSOStartRequest struct {
	Email       string `json:"email"`
	RedirectURI string `json:"redirect_uri"`
	SessionKind string `json:"session_kind"`
}

func (r *SSOStartRequest) Validate() error {
	r.Email = NormalizeEmail(r.Email)
	f := fields{}
	if !validEmail(r.Email) {
		f["email"] = "must be a valid email address"
	}
	if !validOrigin(r.RedirectURI, true) {
		f["redirect_uri"] = "must be an address of the application"
	}
	if err := checkSessionKind(&r.SessionKind); err != "" {
		f["session_kind"] = err
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// OrgPoliciesRequest changes an organization's rules (ENT-7). A field
// that is absent keeps its value.
type OrgPoliciesRequest struct {
	MFARequired           *bool    `json:"mfa_required"`
	SessionMaxSeconds     *int     `json:"session_max_seconds"`
	AllowedAuthMethods    []string `json:"allowed_auth_methods"`
	IPAllowlist           []string `json:"ip_allowlist"`
	EnforceSSO            *bool    `json:"enforce_sso"`
	BreakGlassPrincipalID *string  `json:"break_glass_principal_id"`
}

func (r *OrgPoliciesRequest) Validate() error {
	f := fields{}
	if r.SessionMaxSeconds != nil && *r.SessionMaxSeconds < 0 {
		f["session_max_seconds"] = "must not be negative"
	}
	for _, m := range r.AllowedAuthMethods {
		switch m {
		case constant.MethodPassword, constant.MethodPasskey, constant.MethodOneTimeCode, constant.MethodMagicLink, constant.MethodSocial, constant.MethodEnterprise, constant.MethodEmailLink:
		default:
			f["allowed_auth_methods"] = "holds an unknown method"
		}
	}
	for _, c := range r.IPAllowlist {
		if _, _, err := net.ParseCIDR(c); err != nil {
			if net.ParseIP(c) == nil {
				f["ip_allowlist"] = "each must be an address or a network such as 10.0.0.0/8"
				break
			}
		}
	}
	if r.BreakGlassPrincipalID != nil && *r.BreakGlassPrincipalID != "" && !validUUID(*r.BreakGlassPrincipalID) {
		f["break_glass_principal_id"] = "must be an id"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type CreateDirectoryRequest struct {
	DefaultRole string `json:"default_role"`
}
