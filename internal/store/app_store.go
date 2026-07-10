package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// ErrDuplicateEntityID is returned by Create and UpdateSAMLConfig when a SAML
// entityID is already registered within the same tenant. SAML entityIDs are
// only unique within a tenant boundary, so this is a per-tenant conflict, not a
// global one.
var ErrDuplicateEntityID = errors.New("entityID already registered for tenant")

// appItem wraps tenant.Application with DynamoDB key fields.
type appItem struct {
	PK     string `dynamo:"PK,hash" json:"-"`
	SK     string `dynamo:"SK,range" json:"-"`
	GSI1PK string `dynamo:"GSI1PK" json:"-" index:"GSI1,hash"`
	GSI1SK string `dynamo:"GSI1SK" json:"-" index:"GSI1,range"`
	// EntityID stored at the app-item level for GSI lookup context.
	EntityID string `dynamo:"entityId" json:"entityId"`
	tenant.Application
}

// entityUniqueItem is a marker row that reserves a (tenant, entityID) pair. It
// is written with a conditional put (PutIfNotExists) so that concurrent creates
// racing on the same entityID cannot both succeed: on DynamoDB this maps to
// attribute_not_exists(PK), and on the in-memory store to an atomic
// LoadOrStore. The app item itself uses a random SK, so a conditional put on
// the app item alone would never detect a duplicate entityID — the dedicated
// marker is what makes (tenant, entityID) the enforced uniqueness boundary.
type entityUniqueItem struct {
	PK       string `dynamo:"PK,hash" json:"-"`
	SK       string `dynamo:"SK,range" json:"-"`
	EntityID string `dynamo:"entityId" json:"entityId"`
	AppID    string `dynamo:"appId" json:"appId"`
}

// samlItem wraps tenant.SAMLConfig with DynamoDB key fields.
type samlItem struct {
	PK string `dynamo:"PK,hash" json:"-"`
	SK string `dynamo:"SK,range" json:"-"`
	tenant.SAMLConfig
}

// oidcItem wraps tenant.OIDCConfig with DynamoDB key fields.
type oidcItem struct {
	PK string `dynamo:"PK,hash" json:"-"`
	SK string `dynamo:"SK,range" json:"-"`
	tenant.OIDCConfig
}

// AppStore provides CRUD operations for Application and SAMLConfig.
type AppStore struct {
	db TableAPI
}

// Compile-time check: AppStore implements domain.AppRepository.
var _ domain.AppRepository = (*AppStore)(nil)

// NewAppStore creates a new AppStore.
func NewAppStore(db TableAPI, tableName string) *AppStore {
	return &AppStore{db: db}
}

func appSK(id string) string     { return fmt.Sprintf("APP#%s", id) }
func appSAMLSK(id string) string { return fmt.Sprintf("APP#%s#SAML", id) }
func appOIDCSK(id string) string { return fmt.Sprintf("APP#%s#OIDC", id) }

// entityUniqueSK is the sort key of the (tenant, entityID) uniqueness marker.
// It lives under the tenant's partition (PK=TENANT#<slug>) so the reservation
// is naturally tenant-scoped: two tenants may register the same entityID, but a
// single tenant may not register it twice.
func entityUniqueSK(entityID string) string { return fmt.Sprintf("ENTITYUNIQUE#%s", entityID) }

// entityGSIPK is the GSI1 partition key used to look up a SAML app by
// (tenant, entityID). Tenant is part of the key so a lookup can never return an
// app belonging to a different tenant, even if two tenants share an entityID.
func entityGSIPK(tenantSlug, entityID string) string {
	return fmt.Sprintf("ENTITY#%s#%s", tenantSlug, entityID)
}

// Create stores a new Application + SAMLConfig and returns the generated ID.
func (s *AppStore) Create(ctx context.Context, tenantSlug string, app *tenant.Application, samlCfg *tenant.SAMLConfig) (string, error) {
	id, err := generateID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	app.ID = id
	app.TenantSlug = tenantSlug
	app.CreatedAt = now
	app.UpdatedAt = now

	gsi1PK := ""
	gsi1SK := fmt.Sprintf("TENANT#%s", tenantSlug)
	entityID := ""
	if samlCfg != nil {
		entityID = samlCfg.EntityID
		gsi1PK = entityGSIPK(tenantSlug, entityID)
	} else {
		gsi1PK = fmt.Sprintf("CLIENTID#%s", id)
	}

	// Reserve the (tenant, entityID) pair before writing the app item. This is
	// a conditional put that fails if the pair is already registered for this
	// tenant, closing the race where two concurrent creates would otherwise
	// both land in the GSI under the same entityID. The app item's SK is a
	// random ID, so only this dedicated marker can enforce the constraint.
	if samlCfg != nil {
		marker := entityUniqueItem{
			PK:       tenantPK(tenantSlug),
			SK:       entityUniqueSK(entityID),
			EntityID: entityID,
			AppID:    id,
		}
		if err := s.db.PutIfNotExists(ctx, &marker); err != nil {
			if errors.Is(err, ErrConditionFailed) {
				return "", fmt.Errorf("%w: tenant=%s entityID=%s", ErrDuplicateEntityID, tenantSlug, entityID)
			}
			return "", fmt.Errorf("failed to reserve entityID: %w", err)
		}
	}

	aItem := appItem{
		PK:          tenantPK(tenantSlug),
		SK:          appSK(id),
		GSI1PK:      gsi1PK,
		GSI1SK:      gsi1SK,
		EntityID:    entityID,
		Application: *app,
	}
	if err := s.db.Put(ctx, &aItem); err != nil {
		// Roll back the uniqueness reservation so a failed create does not
		// permanently block the entityID for this tenant.
		if samlCfg != nil {
			_ = s.db.Delete(ctx, tenantPK(tenantSlug), entityUniqueSK(entityID))
		}
		return "", fmt.Errorf("failed to create application: %w", err)
	}

	if samlCfg != nil {
		sItem := samlItem{
			PK:         tenantPK(tenantSlug),
			SK:         appSAMLSK(id),
			SAMLConfig: *samlCfg,
		}
		if err := s.db.Put(ctx, &sItem); err != nil {
			return "", fmt.Errorf("failed to create SAML config: %w", err)
		}
	}

	return id, nil
}

// Get retrieves an Application by tenant slug and app ID.
func (s *AppStore) Get(ctx context.Context, tenantSlug, appID string) (*tenant.Application, error) {
	var item appItem
	if err := s.db.Get(ctx, tenantPK(tenantSlug), appSK(appID), &item); err != nil {
		return nil, fmt.Errorf("failed to get application %q: %w", appID, err)
	}
	item.TenantSlug = tenantSlug
	return &item.Application, nil
}

// GetSAMLConfig retrieves the SAML configuration for an application.
func (s *AppStore) GetSAMLConfig(ctx context.Context, tenantSlug, appID string) (*tenant.SAMLConfig, error) {
	var item samlItem
	if err := s.db.Get(ctx, tenantPK(tenantSlug), appSAMLSK(appID), &item); err != nil {
		return nil, fmt.Errorf("failed to get SAML config for app %q: %w", appID, err)
	}
	return &item.SAMLConfig, nil
}

// GetOIDCConfig retrieves the OIDC configuration for an application.
func (s *AppStore) GetOIDCConfig(ctx context.Context, tenantSlug, appID string) (*tenant.OIDCConfig, error) {
	var item oidcItem
	if err := s.db.Get(ctx, tenantPK(tenantSlug), appOIDCSK(appID), &item); err != nil {
		return nil, fmt.Errorf("failed to get OIDC config for app %q: %w", appID, err)
	}
	return &item.OIDCConfig, nil
}

// UpdateOIDCConfig updates the OIDC configuration for an application.
func (s *AppStore) UpdateOIDCConfig(ctx context.Context, tenantSlug, appID string, cfg *tenant.OIDCConfig) error {
	// Verify the app exists.
	if _, err := s.Get(ctx, tenantSlug, appID); err != nil {
		return fmt.Errorf("failed to get application for OIDC update: %w", err)
	}

	item := oidcItem{
		PK:         tenantPK(tenantSlug),
		SK:         appOIDCSK(appID),
		OIDCConfig: *cfg,
	}
	if err := s.db.Put(ctx, &item); err != nil {
		return fmt.Errorf("failed to update OIDC config: %w", err)
	}
	return nil
}

// GetByTenantEntityID uses the GSI to find an Application + SAMLConfig from a
// (tenant, SAML entityID) pair. Because tenant is part of the GSI partition key
// (ENTITY#<tenant>#<entityID>), the lookup can only ever return an app owned by
// the given tenant: a SAML entityID is unique only within a tenant, and this is
// the query that enforces that boundary at read time. It returns ErrNotFound if
// no app in this tenant declares the entityID.
func (s *AppStore) GetByTenantEntityID(ctx context.Context, tenantSlug, entityID string) (app *tenant.Application, samlCfg *tenant.SAMLConfig, err error) {
	gsiPK := entityGSIPK(tenantSlug, entityID)

	var items []appItem
	if err := s.db.QueryGSI(ctx, "entityId-index", gsiPK, &items); err != nil && err != ErrNotFound {
		return nil, nil, fmt.Errorf("failed to query by entity ID: %w", err)
	}

	if len(items) == 0 {
		return nil, nil, ErrNotFound
	}

	// Defense in depth: the GSI1SK still carries TENANT#<slug>; verify it
	// matches the requested tenant before trusting the item. A mismatch means
	// the GSI key scheme drifted from the SK scheme and must never silently
	// resolve to another tenant's app.
	gsi1SK := items[0].GSI1SK
	if gsi1SK != fmt.Sprintf("TENANT#%s", tenantSlug) {
		return nil, nil, fmt.Errorf("GSI tenant mismatch: got %q, want tenant %q", gsi1SK, tenantSlug)
	}

	appIDVal := items[0].ID
	if appIDVal == "" {
		return nil, nil, fmt.Errorf("missing app ID in GSI result")
	}

	app, err = s.Get(ctx, tenantSlug, appIDVal)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load application after GSI lookup: %w", err)
	}

	samlCfg, err = s.GetSAMLConfig(ctx, tenantSlug, appIDVal)
	if err != nil {
		// SAML config may not exist for non-SAML apps.
		samlCfg = nil
	}

	return app, samlCfg, nil
}

// GetByClientID uses the GSI to find an Application + OIDCConfig from an OIDC client ID.
func (s *AppStore) GetByClientID(ctx context.Context, clientID string) (tenantSlug string, app *tenant.Application, oidcCfg *tenant.OIDCConfig, err error) {
	gsiPK := fmt.Sprintf("CLIENTID#%s", clientID)

	var items []appItem
	if err := s.db.QueryGSI(ctx, "entityId-index", gsiPK, &items); err != nil && err != ErrNotFound {
		return "", nil, nil, fmt.Errorf("failed to query by client ID: %w", err)
	}

	if len(items) == 0 {
		return "", nil, nil, ErrNotFound
	}

	// Extract tenant slug from GSI1SK = "TENANT#<slug>"
	gsi1SK := items[0].GSI1SK
	if !strings.HasPrefix(gsi1SK, "TENANT#") {
		return "", nil, nil, fmt.Errorf("invalid GSI1SK format: %s", gsi1SK)
	}
	tenantSlug = gsi1SK[7:]

	appIDVal := items[0].ID
	if appIDVal == "" {
		return "", nil, nil, fmt.Errorf("missing app ID in GSI result")
	}

	app, err = s.Get(ctx, tenantSlug, appIDVal)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to load application after GSI lookup: %w", err)
	}

	oidcCfg, _ = s.GetOIDCConfig(ctx, tenantSlug, appIDVal)

	return tenantSlug, app, oidcCfg, nil
}

// List returns all Applications for a tenant.
func (s *AppStore) List(ctx context.Context, tenantSlug string) ([]*tenant.Application, error) {
	pk := tenantPK(tenantSlug)
	var items []appItem
	if err := s.db.Query(ctx, pk, "APP#", &items); err != nil {
		return nil, fmt.Errorf("failed to list applications: %w", err)
	}

	var apps []*tenant.Application
	for _, item := range items {
		sk := item.SK
		// Only match APP#<id> (not APP#<id>#SAML or APP#<id>#CLAIM#...)
		suffix := strings.TrimPrefix(sk, "APP#")
		if strings.Contains(suffix, "#") {
			continue
		}

		a := item.Application
		a.TenantSlug = tenantSlug
		apps = append(apps, &a)
	}
	return apps, nil
}

// Update updates an existing Application (not SAML config).
func (s *AppStore) Update(ctx context.Context, tenantSlug string, app *tenant.Application) error {
	if app.ID == "" {
		return fmt.Errorf("application ID is required for update")
	}

	existing, err := s.Get(ctx, tenantSlug, app.ID)
	if err != nil {
		return fmt.Errorf("failed to get existing application: %w", err)
	}

	app.TenantSlug = tenantSlug
	app.CreatedAt = existing.CreatedAt
	app.UpdatedAt = time.Now()

	// Preserve GSI keys -- reload the entityID from the existing item.
	var raw appItem
	if err := s.db.Get(ctx, tenantPK(tenantSlug), appSK(app.ID), &raw); err != nil {
		slog.Error("failed to reload app item for GSI key preservation",
			"tenant", tenantSlug,
			"appId", app.ID,
			"error", err,
		)
		return fmt.Errorf("failed to reload application for update: %w", err)
	}

	aItem := appItem{
		PK:          tenantPK(tenantSlug),
		SK:          appSK(app.ID),
		GSI1PK:      raw.GSI1PK,
		GSI1SK:      raw.GSI1SK,
		EntityID:    raw.EntityID,
		Application: *app,
	}
	if err := s.db.Put(ctx, &aItem); err != nil {
		return fmt.Errorf("failed to update application: %w", err)
	}
	return nil
}

// UpdateSAMLConfig updates the SAML configuration for an application.
func (s *AppStore) UpdateSAMLConfig(ctx context.Context, tenantSlug, appID string, cfg *tenant.SAMLConfig) error {
	// Verify the app exists.
	if _, err := s.Get(ctx, tenantSlug, appID); err != nil {
		return fmt.Errorf("failed to get application for SAML update: %w", err)
	}

	// Reload the app item first so we know the previous entityID. If the
	// entityID is changing, reserve the new (tenant, entityID) pair before we
	// mutate anything, so a rename that collides with another app in the same
	// tenant is rejected rather than corrupting the GSI.
	var raw appItem
	if err := s.db.Get(ctx, tenantPK(tenantSlug), appSK(appID), &raw); err != nil {
		return fmt.Errorf("failed to reload application for SAML update: %w", err)
	}
	oldEntityID := raw.EntityID

	if cfg.EntityID != oldEntityID {
		marker := entityUniqueItem{
			PK:       tenantPK(tenantSlug),
			SK:       entityUniqueSK(cfg.EntityID),
			EntityID: cfg.EntityID,
			AppID:    appID,
		}
		if err := s.db.PutIfNotExists(ctx, &marker); err != nil {
			if errors.Is(err, ErrConditionFailed) {
				return fmt.Errorf("%w: tenant=%s entityID=%s", ErrDuplicateEntityID, tenantSlug, cfg.EntityID)
			}
			return fmt.Errorf("failed to reserve entityID: %w", err)
		}
	}

	sItem := samlItem{
		PK:         tenantPK(tenantSlug),
		SK:         appSAMLSK(appID),
		SAMLConfig: *cfg,
	}
	if err := s.db.Put(ctx, &sItem); err != nil {
		if cfg.EntityID != oldEntityID {
			_ = s.db.Delete(ctx, tenantPK(tenantSlug), entityUniqueSK(cfg.EntityID))
		}
		return fmt.Errorf("failed to update SAML config: %w", err)
	}

	// Update GSI keys on the app item to reflect the new entityID.
	raw.GSI1PK = entityGSIPK(tenantSlug, cfg.EntityID)
	raw.EntityID = cfg.EntityID
	if err := s.db.Put(ctx, &raw); err != nil {
		slog.Error("failed to update GSI keys after SAML config update",
			"tenant", tenantSlug,
			"appId", appID,
			"entityId", cfg.EntityID,
			"error", err,
		)
		return fmt.Errorf("failed to update application GSI keys: %w", err)
	}

	// Release the previous entityID reservation now that the rename is durable.
	if oldEntityID != "" && cfg.EntityID != oldEntityID {
		_ = s.db.Delete(ctx, tenantPK(tenantSlug), entityUniqueSK(oldEntityID))
	}

	return nil
}

// Delete removes an Application and its SAML config.
func (s *AppStore) Delete(ctx context.Context, tenantSlug, appID string) error {
	// Reload the app item first so we can release its entityID reservation.
	var raw appItem
	rawErr := s.db.Get(ctx, tenantPK(tenantSlug), appSK(appID), &raw)
	if rawErr != nil {
		return fmt.Errorf("failed to get application for deletion: %w", rawErr)
	}
	if err := s.db.Delete(ctx, tenantPK(tenantSlug), appSK(appID)); err != nil {
		return fmt.Errorf("failed to delete application: %w", err)
	}
	// Best-effort delete of SAML config.
	_ = s.db.Delete(ctx, tenantPK(tenantSlug), appSAMLSK(appID))
	// Best-effort delete of OIDC config.
	_ = s.db.Delete(ctx, tenantPK(tenantSlug), appOIDCSK(appID))
	// Best-effort release of the (tenant, entityID) uniqueness reservation so
	// the entityID can be re-registered by this tenant after deletion.
	if raw.EntityID != "" {
		_ = s.db.Delete(ctx, tenantPK(tenantSlug), entityUniqueSK(raw.EntityID))
	}
	return nil
}

// SetStatus updates only the status field of an Application.
func (s *AppStore) SetStatus(ctx context.Context, tenantSlug, appID, status string) error {
	app, err := s.Get(ctx, tenantSlug, appID)
	if err != nil {
		return err
	}
	app.Status = status
	return s.Update(ctx, tenantSlug, app)
}
