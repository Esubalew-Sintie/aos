// Package tenant creates tenants, finds the tenant behind a key, and
// keeps each tenant's keys.
package tenant

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/storage"
	"github.com/flash-software-technology/aos/platform/jwt"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/postgres"
	"github.com/flash-software-technology/aos/platform/secret"
)

// Module is both module.Tenant and module.KeyRing.
type Module struct {
	db     *postgres.DB
	repo   storage.TenantRepository
	audit  storage.AuditRepository
	master *secret.MasterKey
	log    logger.Logger

	// Decrypted keys, held in memory only. Data keys never change once
	// made, so they are cached by id for the life of the process.
	mu          sync.RWMutex
	dataKeys    map[string][]byte     // data key id -> key
	activeKeys  map[string]string     // tenant id -> its current data key id
	signingKeys map[string]signingKey // tenant id -> its current signing key
}

type signingKey struct {
	kid string
	key ed25519.PrivateKey
}

func NewTenantModule(db *postgres.DB, repo storage.TenantRepository, audit storage.AuditRepository,
	master *secret.MasterKey, log logger.Logger) *Module {
	return &Module{
		db: db, repo: repo, audit: audit, master: master, log: log,
		dataKeys:    map[string][]byte{},
		activeKeys:  map[string]string{},
		signingKeys: map[string]signingKey{},
	}
}

func (m *Module) Create(ctx context.Context, req request.CreateTenantRequest) (*response.CreateTenantResponse, error) {
	var out *response.CreateTenantResponse
	err := m.db.Switching(ctx, func(tx pgx.Tx) (err error) {
		out, err = m.CreateIn(ctx, tx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CreateIn creates a tenant inside a switching transaction. It leaves the
// transaction scoped to the new tenant.
func (m *Module) CreateIn(ctx context.Context, tx pgx.Tx, req request.CreateTenantRequest) (*response.CreateTenantResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	// Everything secret is made before anything is written.
	env := "test"
	if req.Environment == constant.EnvProduction {
		env = "live"
	}
	publishable := "pk_" + env + "_" + secret.HexID(12)
	secretPublicID := "sk_" + env + "_" + secret.HexID(12)
	secretPart := secret.Token(32)

	dataKey := secret.NewDataKey()
	wrapped, err := m.master.Wrap(dataKey)
	if err != nil {
		return nil, fmt.Errorf("create tenant: wrap data key: %w", err)
	}
	public, private, err := jwt.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("create tenant: make signing key: %w", err)
	}
	kid := secret.HexID(8)

	var tenantID string
	err = func() error {
		// The tenant row is the platform's to create.
		if err := postgres.SetPlatform(ctx, tx); err != nil {
			return err
		}
		tenantID, err = m.repo.CreateTenant(ctx, tx, model.NewTenant{
			Slug: req.Slug, Name: req.Name, Kind: req.Kind, Environment: req.Environment,
			Settings: map[string]any{"app_url": strings.TrimRight(req.AppURL, "/")},
		})
		if err != nil {
			return err
		}

		// Everything inside it is written as that tenant.
		if err := postgres.SetTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		if err := m.repo.CreateResourceType(ctx, tx, tenantID, constant.ResourceTypeTenant, constant.SourceSystem); err != nil {
			return err
		}
		if req.Kind == constant.KindMulti {
			if err := m.repo.CreateResourceType(ctx, tx, tenantID, constant.ResourceTypeOrganization, constant.SourceSystem); err != nil {
				return err
			}
		}
		if _, err := m.repo.CreateRootResource(ctx, tx, tenantID); err != nil {
			return err
		}
		if _, err := m.repo.CreateOwnerRole(ctx, tx, tenantID); err != nil {
			return err
		}
		if err := m.repo.CreateSystemPermissions(ctx, tx, tenantID, constant.SystemPermissions); err != nil {
			return err
		}

		dataKeyID, err := m.repo.CreateDataKey(ctx, tx, tenantID, wrapped, m.master.Ref())
		if err != nil {
			return err
		}
		// The private key is bound to this tenant and this key id: it
		// cannot be decrypted as anything else.
		sealed, err := secret.Seal(dataKey, private, signingContext(tenantID, kid))
		if err != nil {
			return err
		}
		if err := m.repo.CreateSigningKey(ctx, tx, tenantID, model.SigningKey{
			KID: kid, Public: public, PrivateEncrypted: sealed, DataKeyID: dataKeyID,
		}); err != nil {
			return err
		}

		if err := m.repo.CreateTenantKey(ctx, tx, tenantID, constant.KeyKindPublishable, publishable, nil); err != nil {
			return err
		}
		if err := m.repo.CreateTenantKey(ctx, tx, tenantID, constant.KeyKindSecret, secretPublicID, secret.Hash(secretPart)); err != nil {
			return err
		}
		for _, origin := range req.AllowedOrigins {
			if err := m.repo.AddAllowedOrigin(ctx, tx, tenantID, origin); err != nil {
				return err
			}
		}

		return m.audit.Append(ctx, tx, tenantID, model.AuditEntry{
			Action: "tenant.created", Result: model.AuditSuccess,
			TargetType: "tenant", TargetID: tenantID,
			Data: map[string]any{"kind": req.Kind, "environment": req.Environment},
		})
	}()
	if postgres.IsUniqueViolation(err) {
		return nil, errors.Conflict("slug_taken", "this name is already taken. choose another one")
	}
	if err != nil {
		return nil, fmt.Errorf("create tenant: %w", err)
	}

	return &response.CreateTenantResponse{
		TenantID:       tenantID,
		Slug:           req.Slug,
		PublishableKey: publishable,
		SecretKey:      secretPublicID + "." + secretPart,
	}, nil
}

// NewSecretKey makes another secret key for a tenant, for rotation
// (HOST-3). It runs inside the tenant's scope and returns the key once.
func (m *Module) NewSecretKey(ctx context.Context, tx pgx.Tx, t *model.Tenant) (string, error) {
	env := "test"
	if t.Environment == constant.EnvProduction {
		env = "live"
	}
	publicID := "sk_" + env + "_" + secret.HexID(12)
	secretPart := secret.Token(32)
	if err := m.repo.CreateTenantKey(ctx, tx, t.ID, constant.KeyKindSecret, publicID, secret.Hash(secretPart)); err != nil {
		return "", err
	}
	return publicID + "." + secretPart, nil
}

func (m *Module) ResolveKey(ctx context.Context, presented string) (*model.Tenant, string, error) {
	// A secret key is "<public id>.<secret>". A publishable key has no secret.
	publicID, secretPart, _ := strings.Cut(presented, ".")
	if publicID == "" || len(presented) > 200 {
		return nil, "", errors.ErrInvalidKey
	}

	var key *model.ResolvedKey
	err := m.db.Resolver(ctx, func(tx pgx.Tx) (err error) {
		key, err = m.repo.ResolveKey(ctx, tx, publicID)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	if key == nil {
		return nil, "", errors.ErrInvalidKey
	}
	switch key.Kind {
	case constant.KeyKindSecret:
		if !secret.Equal(secret.Hash(secretPart), key.SecretHash) {
			return nil, "", errors.ErrInvalidKey
		}
	case constant.KeyKindPublishable:
		if secretPart != "" {
			return nil, "", errors.ErrInvalidKey
		}
	default:
		return nil, "", errors.ErrInvalidKey
	}

	var t *model.Tenant
	err = m.db.Tenant(ctx, key.TenantID, func(tx pgx.Tx) (err error) {
		t, err = m.repo.GetTenant(ctx, tx, key.TenantID)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	if t == nil {
		return nil, "", errors.ErrInvalidKey
	}
	return t, key.Kind, nil
}

func (m *Module) FindBySlug(ctx context.Context, slug string) (*model.Tenant, error) {
	var tenantID string
	err := m.db.Resolver(ctx, func(tx pgx.Tx) error {
		id, _, err := m.repo.ResolveSlug(ctx, tx, slug)
		tenantID = id
		return err
	})
	if err != nil {
		return nil, err
	}
	if tenantID == "" {
		return nil, errors.NotFound("tenant")
	}
	var t *model.Tenant
	err = m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) (err error) {
		t, err = m.repo.GetTenant(ctx, tx, tenantID)
		return err
	})
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, errors.NotFound("tenant")
	}
	return t, nil
}

func (m *Module) IsAllowedOrigin(ctx context.Context, tenantID, origin string) (bool, error) {
	var ok bool
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) (err error) {
		ok, err = m.repo.IsAllowedOrigin(ctx, tx, tenantID, origin)
		return err
	})
	return ok, err
}

func (m *Module) JWKS(ctx context.Context, t *model.Tenant) (*response.JWKSResponse, error) {
	var keys []model.SigningKey
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		keys, err = m.repo.ListSigningKeys(ctx, tx, t.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := &response.JWKSResponse{Keys: make([]response.JWK, 0, len(keys))}
	for _, k := range keys {
		j := jwt.PublicJWK(k.KID, ed25519.PublicKey(k.Public))
		out.Keys = append(out.Keys, response.JWK{Kty: j.Kty, Crv: j.Crv, X: j.X, Kid: j.Kid, Use: j.Use, Alg: j.Alg})
	}
	return out, nil
}

// ---- module.KeyRing ----

func (m *Module) DataKey(ctx context.Context, tx pgx.Tx, tenantID string) (string, []byte, error) {
	m.mu.RLock()
	id, ok := m.activeKeys[tenantID]
	key := m.dataKeys[id]
	m.mu.RUnlock()
	if ok && key != nil {
		return id, key, nil
	}

	stored, err := m.repo.GetActiveDataKey(ctx, tx, tenantID)
	if err != nil {
		return "", nil, err
	}
	key, err = m.master.Unwrap(stored.Wrapped)
	if err != nil {
		return "", nil, fmt.Errorf("data key %s: %w", stored.ID, err)
	}
	m.mu.Lock()
	m.dataKeys[stored.ID] = key
	m.activeKeys[tenantID] = stored.ID
	m.mu.Unlock()
	return stored.ID, key, nil
}

func (m *Module) DataKeyByID(ctx context.Context, tx pgx.Tx, tenantID, id string) ([]byte, error) {
	m.mu.RLock()
	key := m.dataKeys[id]
	m.mu.RUnlock()
	if key != nil {
		return key, nil
	}

	// The lookup names the tenant, so one tenant can never be handed
	// another tenant's key, even with the right id.
	stored, err := m.repo.GetDataKey(ctx, tx, tenantID, id)
	if err != nil {
		return nil, err
	}
	key, err = m.master.Unwrap(stored.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("data key %s: %w", id, err)
	}
	m.mu.Lock()
	m.dataKeys[id] = key
	m.mu.Unlock()
	return key, nil
}

func (m *Module) SigningKey(ctx context.Context, tx pgx.Tx, tenantID string) (string, ed25519.PrivateKey, error) {
	m.mu.RLock()
	cached, ok := m.signingKeys[tenantID]
	m.mu.RUnlock()
	if ok {
		return cached.kid, cached.key, nil
	}

	stored, err := m.repo.GetActiveSigningKey(ctx, tx, tenantID)
	if err != nil {
		return "", nil, err
	}
	dataKey, err := m.DataKeyByID(ctx, tx, tenantID, stored.DataKeyID)
	if err != nil {
		return "", nil, err
	}
	private, err := secret.Open(dataKey, stored.PrivateEncrypted, signingContext(tenantID, stored.KID))
	if err != nil {
		return "", nil, fmt.Errorf("signing key %s: %w", stored.KID, err)
	}
	if len(private) != ed25519.PrivateKeySize {
		return "", nil, fmt.Errorf("signing key %s: wrong length", stored.KID)
	}
	m.mu.Lock()
	m.signingKeys[tenantID] = signingKey{kid: stored.KID, key: ed25519.PrivateKey(private)}
	m.mu.Unlock()
	return stored.KID, ed25519.PrivateKey(private), nil
}

func signingContext(tenantID, kid string) []byte {
	return []byte("aos:signing-key|" + tenantID + "|" + kid)
}

func (m *Module) Get(ctx context.Context, tenantID string) (*model.Tenant, error) {
	if !postgres.IsUUID(tenantID) {
		return nil, nil
	}
	var t *model.Tenant
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) (err error) {
		t, err = m.repo.GetTenant(ctx, tx, tenantID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("get tenant: %w", err)
	}
	return t, nil
}

func (m *Module) PublicKey(ctx context.Context, tx pgx.Tx, tenantID, kid string) (ed25519.PublicKey, error) {
	keys, err := m.repo.ListSigningKeys(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.KID == kid {
			return ed25519.PublicKey(k.Public), nil
		}
	}
	return nil, nil
}
