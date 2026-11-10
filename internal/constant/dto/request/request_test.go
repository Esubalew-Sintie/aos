package request

import (
	"strings"
	"testing"

	"github.com/flash-software-technology/aos/internal/constant/errors"
)

// failed returns the fields a validation error names.
func failed(err error) map[string]string {
	if err == nil {
		return nil
	}
	appErr, ok := errors.AsAppError(err)
	if !ok {
		return map[string]string{"?": err.Error()}
	}
	return appErr.Details
}

func TestSignUpRequest(t *testing.T) {
	ok := SignUpRequest{Email: "  Hana@Example.COM ", Password: "long enough"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a good request was refused: %v", failed(err))
	}
	if ok.Email != "hana@example.com" {
		t.Fatalf("the email was not normalised: %q", ok.Email)
	}

	for name, c := range map[string]struct {
		req   SignUpRequest
		field string
	}{
		"no at sign":        {SignUpRequest{Email: "hana.example.com", Password: "long enough"}, "email"},
		"no dot in domain":  {SignUpRequest{Email: "hana@localhost", Password: "long enough"}, "email"},
		"a display name":    {SignUpRequest{Email: "Hana <hana@example.com>", Password: "long enough"}, "email"},
		"two addresses":     {SignUpRequest{Email: "a@example.com, b@example.com", Password: "long enough"}, "email"},
		"empty email":       {SignUpRequest{Password: "long enough"}, "email"},
		"short password":    {SignUpRequest{Email: "hana@example.com", Password: "seven77"}, "password"},
		"enormous password": {SignUpRequest{Email: "hana@example.com", Password: strings.Repeat("x", 257)}, "password"},
		"enormous name":     {SignUpRequest{Email: "hana@example.com", Password: "long enough", Name: strings.Repeat("x", 201)}, "name"},
	} {
		if got := failed(c.req.Validate()); got[c.field] == "" {
			t.Errorf("%s: want a problem with %q, got %v", name, c.field, got)
		}
	}

	// Length is counted in characters, not bytes: eight Amharic letters pass.
	amharic := SignUpRequest{Email: "hana@example.com", Password: "ሰላምሰላምሰላምሰላ"}
	if err := amharic.Validate(); err != nil {
		t.Errorf("an eight-character password in another script was refused: %v", failed(err))
	}
}

// Sign-in must not say whether the email is well formed or the password
// long enough. It checks only that both are present.
func TestSignInRequestDoesNotJudgeItsInput(t *testing.T) {
	odd := SignInRequest{Email: "not-an-email", Password: "x"}
	if err := odd.Validate(); err != nil {
		t.Fatalf("sign-in judged its input: %v", failed(err))
	}
	if got := failed((&SignInRequest{}).Validate()); got["email"] == "" || got["password"] == "" {
		t.Fatalf("missing fields were not reported: %v", got)
	}
}

func TestPermissionNamesAndPatterns(t *testing.T) {
	for name, want := range map[string]bool{
		"payment.refund": true, "payment": true, "a.b.c_d.e1": true,
		"Payment.refund": false, "payment..refund": false, ".payment": false, "payment.": false,
		"payment refund": false, "payment.*": false, "*": false, "1payment": false, "": false,
	} {
		if got := validPermissionName(name); got != want {
			t.Errorf("name %q: got %v, want %v", name, got, want)
		}
	}
	for pattern, want := range map[string]bool{
		"*": true, "payment.*": true, "payment.refund": true, "a.b.*": true,
		"payment.*.read": false, "*.read": false, "pay*": false, "**": false, "": false,
	} {
		if got := validPermissionPattern(pattern); got != want {
			t.Errorf("pattern %q: got %v, want %v", pattern, got, want)
		}
	}
}

func TestCreateTenantRequest(t *testing.T) {
	ok := CreateTenantRequest{Slug: "pay-gate", Name: "PayGate", AppURL: "https://app.example.com/base", AllowedOrigins: []string{"https://app.example.com", "http://localhost:3000"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a good request was refused: %v", failed(err))
	}
	if ok.Kind != "single" || ok.Environment != "development" {
		t.Fatalf("defaults were not applied: %+v", ok)
	}
	for name, c := range map[string]struct {
		change func(*CreateTenantRequest)
		field  string
	}{
		"upper-case slug":       {func(r *CreateTenantRequest) { r.Slug = "PayGate" }, "slug"},
		"one-letter slug":       {func(r *CreateTenantRequest) { r.Slug = "p" }, "slug"},
		"no name":               {func(r *CreateTenantRequest) { r.Name = " " }, "name"},
		"unknown kind":          {func(r *CreateTenantRequest) { r.Kind = "huge" }, "kind"},
		"unknown environment":   {func(r *CreateTenantRequest) { r.Environment = "prod" }, "environment"},
		"origin with a path":    {func(r *CreateTenantRequest) { r.AllowedOrigins = []string{"https://app.example.com/x"} }, "allowed_origins"},
		"origin with no scheme": {func(r *CreateTenantRequest) { r.AllowedOrigins = []string{"app.example.com"} }, "allowed_origins"},
		"wildcard origin":       {func(r *CreateTenantRequest) { r.AllowedOrigins = []string{"*"} }, "allowed_origins"},
		"javascript app url":    {func(r *CreateTenantRequest) { r.AppURL = "javascript:alert(1)" }, "app_url"},
	} {
		req := CreateTenantRequest{Slug: "pay-gate", Name: "PayGate"}
		c.change(&req)
		if got := failed(req.Validate()); got[c.field] == "" {
			t.Errorf("%s: want a problem with %q, got %v", name, c.field, got)
		}
	}
}
