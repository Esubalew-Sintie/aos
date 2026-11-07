package response

// CreateTenantResponse is shown once, when a tenant is created. The
// secret key cannot be shown again: only its hash is stored.
type CreateTenantResponse struct {
	TenantID       string `json:"tenant_id"`
	Slug           string `json:"slug"`
	PublishableKey string `json:"publishable_key"`
	SecretKey      string `json:"secret_key"`
}
