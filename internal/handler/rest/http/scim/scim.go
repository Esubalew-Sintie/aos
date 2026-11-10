// Package scim serves directory sync in the SCIM 2.0 shape (user-flow
// ENT-5). The identity provider calls it with the token it was given.
package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/platform/logger"
)

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

type SCIMHandler struct {
	enterprise module.Enterprise
	logger     logger.Logger
}

func NewSCIMHandler(enterprise module.Enterprise, logger logger.Logger) rest.SCIMHandler {
	return &SCIMHandler{enterprise: enterprise, logger: logger}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (h *SCIMHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	appErr, ok := errors.AsAppError(err)
	if !ok {
		h.logger.Error(r.Context(), "scim request failed", "error", err.Error(), "request_id", middleware.MetaFrom(r.Context()).RequestID)
		appErr = errors.ErrUnexpected
	}
	body := map[string]any{"schemas": []string{schemaError}, "status": strconv.Itoa(appErr.Status), "detail": appErr.Message}
	if appErr.Code == "uniqueness" {
		body["scimType"] = "uniqueness"
	}
	writeJSON(w, appErr.Status, body)
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"schemas": []string{schemaError}, "status": "400", "detail": "the body is not valid JSON"})
		return false
	}
	return true
}

// ---- shapes ----

type scimName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

type scimUser struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        *scimName   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []scimEmail `json:"emails,omitempty"`
	Active      *bool       `json:"active,omitempty"`
	Meta        *scimMeta   `json:"meta,omitempty"`
}

type scimMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

type scimGroup struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []scimMember `json:"members"`
	Meta        *scimMeta    `json:"meta,omitempty"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
}

func toUser(u *model.DirectoryUser) scimUser {
	active := u.Active
	return scimUser{
		Schemas: []string{schemaUser}, ID: u.PrincipalID, ExternalID: u.ExternalID, UserName: u.Email,
		Name: &scimName{Formatted: u.Name}, DisplayName: u.Name, Emails: []scimEmail{{Value: u.Email, Primary: true}}, Active: &active,
		Meta: &scimMeta{ResourceType: "User", Created: u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")},
	}
}

func toGroup(g *model.Group) scimGroup {
	members := make([]scimMember, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, scimMember{Value: m})
	}
	return scimGroup{Schemas: []string{schemaGroup}, ID: g.ID, ExternalID: g.ExternalID, DisplayName: g.Name, Members: members,
		Meta: &scimMeta{ResourceType: "Group", Created: g.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")}}
}

func list(resources []any) map[string]any {
	return map[string]any{"schemas": []string{schemaList}, "totalResults": len(resources), "startIndex": 1, "itemsPerPage": len(resources), "Resources": resources}
}

// (userName|externalId) eq "value"
var filterPattern = regexp.MustCompile(`^(userName|externalId|emails\.value)\s+eq\s+"([^"]*)"$`)

func (u scimUser) email() string {
	if u.UserName != "" && strings.Contains(u.UserName, "@") {
		return u.UserName
	}
	for _, e := range u.Emails {
		if e.Primary || len(u.Emails) == 1 {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return u.UserName
}

func (u scimUser) fullName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if u.Name != nil {
		if u.Name.Formatted != "" {
			return u.Name.Formatted
		}
		return strings.TrimSpace(u.Name.GivenName + " " + u.Name.FamilyName)
	}
	return ""
}

// ---- service provider ----

func (h *SCIMHandler) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":   map[string]any{"supported": true}, "bulk": map[string]any{"supported": false}, "filter": map[string]any{"supported": true, "maxResults": 200},
		"changePassword": map[string]any{"supported": false}, "sort": map[string]any{"supported": false}, "etag": map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token", "description": "The sync token from the setup page"}},
	})
}

// ---- users ----

func (h *SCIMHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	d := middleware.DirectoryFrom(r.Context())
	filterEmail := ""
	if f := r.URL.Query().Get("filter"); f != "" {
		m := filterPattern.FindStringSubmatch(strings.TrimSpace(f))
		if m == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"schemas": []string{schemaError}, "status": "400", "scimType": "invalidFilter", "detail": "only userName eq, externalId eq and emails.value eq are supported"})
			return
		}
		if m[1] == "externalId" {
			u, err := h.enterprise.SCIMGetUser(r.Context(), d.TenantID, d.DirectoryID, "")
			_ = u
			_ = err
			// externalId lookups go through the module by external id.
			users, err := h.enterprise.SCIMListUsers(r.Context(), d.TenantID, d.DirectoryID, "")
			if err != nil {
				h.fail(w, r, err)
				return
			}
			var resources []any
			for i := range users {
				if users[i].ExternalID == m[2] {
					resources = append(resources, toUser(&users[i]))
				}
			}
			writeJSON(w, http.StatusOK, list(resources))
			return
		}
		filterEmail = m[2]
	}
	users, err := h.enterprise.SCIMListUsers(r.Context(), d.TenantID, d.DirectoryID, filterEmail)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	resources := make([]any, 0, len(users))
	for i := range users {
		resources = append(resources, toUser(&users[i]))
	}
	writeJSON(w, http.StatusOK, list(resources))
}

func (h *SCIMHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	d := middleware.DirectoryFrom(r.Context())
	u, err := h.enterprise.SCIMGetUser(r.Context(), d.TenantID, d.DirectoryID, chi.URLParam(r, "id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUser(u))
}

func (h *SCIMHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var in scimUser
	if !decode(w, r, &in) {
		return
	}
	d := middleware.DirectoryFrom(r.Context())
	active := in.Active == nil || *in.Active
	u, err := h.enterprise.SCIMCreateUser(r.Context(), d.TenantID, d.DirectoryID, in.ExternalID, in.email(), in.fullName(), active)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toUser(u))
}

func (h *SCIMHandler) ReplaceUser(w http.ResponseWriter, r *http.Request) {
	var in scimUser
	if !decode(w, r, &in) {
		return
	}
	d := middleware.DirectoryFrom(r.Context())
	email, name := in.email(), in.fullName()
	active := in.Active == nil || *in.Active
	u, err := h.enterprise.SCIMUpdateUser(r.Context(), d.TenantID, d.DirectoryID, chi.URLParam(r, "id"), &email, &name, &active)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUser(u))
}

type patchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

type patchRequest struct {
	Schemas    []string  `json:"schemas"`
	Operations []patchOp `json:"Operations"`
}

func (h *SCIMHandler) PatchUser(w http.ResponseWriter, r *http.Request) {
	var in patchRequest
	if !decode(w, r, &in) {
		return
	}
	var email, name *string
	var active *bool
	setField := func(path string, value any) {
		switch strings.ToLower(path) {
		case "active":
			switch v := value.(type) {
			case bool:
				active = &v
			case string:
				b := strings.EqualFold(v, "true")
				active = &b
			}
		case "username", "emails[type eq \"work\"].value", "emails[primary eq true].value":
			if s, ok := value.(string); ok {
				email = &s
			}
		case "displayname", "name.formatted":
			if s, ok := value.(string); ok {
				name = &s
			}
		}
	}
	for _, op := range in.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		if op.Path != "" {
			setField(op.Path, op.Value)
			continue
		}
		if fieldsMap, ok := op.Value.(map[string]any); ok {
			for k, v := range fieldsMap {
				setField(k, v)
			}
		}
	}
	d := middleware.DirectoryFrom(r.Context())
	u, err := h.enterprise.SCIMUpdateUser(r.Context(), d.TenantID, d.DirectoryID, chi.URLParam(r, "id"), email, name, active)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUser(u))
}

func (h *SCIMHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	d := middleware.DirectoryFrom(r.Context())
	if err := h.enterprise.SCIMDeleteUser(r.Context(), d.TenantID, d.DirectoryID, chi.URLParam(r, "id")); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- groups ----

func (h *SCIMHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	d := middleware.DirectoryFrom(r.Context())
	groups, err := h.enterprise.SCIMListGroups(r.Context(), d.TenantID, d.DirectoryID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	filterName := ""
	if f := r.URL.Query().Get("filter"); f != "" {
		m := regexp.MustCompile(`^(displayName|externalId)\s+eq\s+"([^"]*)"$`).FindStringSubmatch(strings.TrimSpace(f))
		if m == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"schemas": []string{schemaError}, "status": "400", "scimType": "invalidFilter", "detail": "only displayName eq and externalId eq are supported"})
			return
		}
		filterName = m[1] + "=" + m[2]
	}
	resources := make([]any, 0, len(groups))
	for i := range groups {
		if filterName != "" {
			if filterName != "displayName="+groups[i].Name && filterName != "externalId="+groups[i].ExternalID {
				continue
			}
		}
		resources = append(resources, toGroup(&groups[i]))
	}
	writeJSON(w, http.StatusOK, list(resources))
}

func (h *SCIMHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	d := middleware.DirectoryFrom(r.Context())
	g, err := h.enterprise.SCIMGetGroup(r.Context(), d.TenantID, d.DirectoryID, chi.URLParam(r, "id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toGroup(g))
}

func memberIDs(members []scimMember) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.Value)
	}
	return out
}

func (h *SCIMHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var in scimGroup
	if !decode(w, r, &in) {
		return
	}
	d := middleware.DirectoryFrom(r.Context())
	g, err := h.enterprise.SCIMCreateGroup(r.Context(), d.TenantID, d.DirectoryID, in.ExternalID, in.DisplayName, memberIDs(in.Members))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toGroup(g))
}

func (h *SCIMHandler) ReplaceGroup(w http.ResponseWriter, r *http.Request) {
	var in scimGroup
	if !decode(w, r, &in) {
		return
	}
	d := middleware.DirectoryFrom(r.Context())
	members := memberIDs(in.Members)
	if members == nil {
		members = []string{}
	}
	g, err := h.enterprise.SCIMUpdateGroup(r.Context(), d.TenantID, d.DirectoryID, chi.URLParam(r, "id"), &in.DisplayName, members, nil, nil)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toGroup(g))
}

var memberFilter = regexp.MustCompile(`members\[value\s+eq\s+"([^"]+)"\]`)

func (h *SCIMHandler) PatchGroup(w http.ResponseWriter, r *http.Request) {
	var in patchRequest
	if !decode(w, r, &in) {
		return
	}
	var name *string
	var replaceAll []string
	var add, remove []string
	values := func(v any) []string {
		var out []string
		switch x := v.(type) {
		case []any:
			for _, item := range x {
				if m, ok := item.(map[string]any); ok {
					if s, ok := m["value"].(string); ok {
						out = append(out, s)
					}
				} else if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
		case map[string]any:
			if s, ok := x["value"].(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	for _, op := range in.Operations {
		lower := strings.ToLower(op.Path)
		switch strings.ToLower(op.Op) {
		case "replace":
			switch {
			case lower == "displayname":
				if s, ok := op.Value.(string); ok {
					name = &s
				}
			case lower == "members":
				replaceAll = values(op.Value)
				if replaceAll == nil {
					replaceAll = []string{}
				}
			case op.Path == "":
				if m, ok := op.Value.(map[string]any); ok {
					if s, ok := m["displayName"].(string); ok {
						name = &s
					}
					if mem, ok := m["members"]; ok {
						replaceAll = values(mem)
					}
				}
			}
		case "add":
			if lower == "members" || op.Path == "" {
				if m, ok := op.Value.(map[string]any); ok && op.Path == "" {
					add = append(add, values(m["members"])...)
				} else {
					add = append(add, values(op.Value)...)
				}
			}
		case "remove":
			if m := memberFilter.FindStringSubmatch(op.Path); m != nil {
				remove = append(remove, m[1])
			} else if lower == "members" {
				if vs := values(op.Value); len(vs) > 0 {
					remove = append(remove, vs...)
				} else {
					replaceAll = []string{}
				}
			}
		}
	}
	d := middleware.DirectoryFrom(r.Context())
	g, err := h.enterprise.SCIMUpdateGroup(r.Context(), d.TenantID, d.DirectoryID, chi.URLParam(r, "id"), name, replaceAll, add, remove)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toGroup(g))
}

func (h *SCIMHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	d := middleware.DirectoryFrom(r.Context())
	if err := h.enterprise.SCIMDeleteGroup(r.Context(), d.TenantID, d.DirectoryID, chi.URLParam(r, "id")); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var _ = fmt.Sprint
