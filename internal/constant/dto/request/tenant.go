package request

import (
	"net/url"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/errors"
)

type CreateTenantRequest struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Environment string `json:"environment"`
	// AppURL is the application's own address. Links in emails point there.
	AppURL string `json:"app_url"`
	// AllowedOrigins are the web addresses that may call the API from a browser.
	AllowedOrigins []string `json:"allowed_origins"`
}

func (r *CreateTenantRequest) Validate() error {
	if r.Kind == "" {
		r.Kind = constant.KindSingle
	}
	if r.Environment == "" {
		r.Environment = constant.EnvDevelopment
	}
	f := fields{}
	if !slugPattern.MatchString(r.Slug) {
		f["slug"] = "must be 2 to 63 lower-case letters, digits or hyphens"
	}
	f.require("name", r.Name)
	if r.Kind != constant.KindSingle && r.Kind != constant.KindMulti {
		f["kind"] = "must be single or multi"
	}
	switch r.Environment {
	case constant.EnvDevelopment, constant.EnvStaging, constant.EnvProduction:
	default:
		f["environment"] = "must be development, staging or production"
	}
	if r.AppURL != "" && !validOrigin(r.AppURL, true) {
		f["app_url"] = "must be an address such as https://app.example.com"
	}
	for _, o := range r.AllowedOrigins {
		if !validOrigin(o, false) {
			f["allowed_origins"] = "each must be an origin such as https://app.example.com, with no path"
			break
		}
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// validOrigin checks a web address. An origin has a scheme and a host
// and nothing after them.
func validOrigin(raw string, allowPath bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return allowPath || u.Path == ""
}
