package onboarding

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- In-memory fakes (scoped to this test file) ---

type fakeTenantRepo struct {
	tenants map[string]*tenant.Tenant
}

func newFakeTenantRepo() *fakeTenantRepo {
	return &fakeTenantRepo{tenants: map[string]*tenant.Tenant{}}
}

func (f *fakeTenantRepo) Create(ctx context.Context, t *tenant.Tenant) error {
	if _, exists := f.tenants[t.Slug]; exists {
		return errors.New("already exists")
	}
	cp := *t
	f.tenants[t.Slug] = &cp
	return nil
}

func (f *fakeTenantRepo) Get(ctx context.Context, slug string) (*tenant.Tenant, error) {
	t, ok := f.tenants[slug]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *t
	return &cp, nil
}

func (f *fakeTenantRepo) Update(ctx context.Context, t *tenant.Tenant) error {
	if _, exists := f.tenants[t.Slug]; !exists {
		return errors.New("not found")
	}
	cp := *t
	f.tenants[t.Slug] = &cp
	return nil
}

func (f *fakeTenantRepo) Delete(ctx context.Context, slug string) error {
	delete(f.tenants, slug)
	return nil
}

func (f *fakeTenantRepo) List(ctx context.Context) ([]*tenant.Tenant, error) {
	out := make([]*tenant.Tenant, 0, len(f.tenants))
	for _, t := range f.tenants {
		cp := *t
		out = append(out, &cp)
	}
	return out, nil
}

type fakeStateRepo struct {
	states map[string]*domain.OnboardingState
}

func newFakeStateRepo() *fakeStateRepo {
	return &fakeStateRepo{states: map[string]*domain.OnboardingState{}}
}

func (f *fakeStateRepo) Get(ctx context.Context, slug string) (*domain.OnboardingState, error) {
	s, ok := f.states[slug]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *s
	return &cp, nil
}

func (f *fakeStateRepo) Put(ctx context.Context, s *domain.OnboardingState) error {
	cp := *s
	f.states[s.TenantSlug] = &cp
	return nil
}

func (f *fakeStateRepo) Delete(ctx context.Context, slug string) error {
	delete(f.states, slug)
	return nil
}

type fakeAudit struct{ events []string }

func (a *fakeAudit) LogStep(ctx context.Context, tenantSlug, flowID, stepType, spEntityID, userID string, payload map[string]string) error {
	a.events = append(a.events, stepType)
	return nil
}

func (a *fakeAudit) GetFlow(ctx context.Context, tenantSlug, flowID string) ([]domain.FlowStep, error) {
	return nil, nil
}

func (a *fakeAudit) GetRecentSteps(ctx context.Context, tenantSlug string, limit int) ([]domain.FlowStep, error) {
	return nil, nil
}

func newService() (*Service, *fakeTenantRepo, *fakeStateRepo, *fakeAudit) {
	tr, sr, au := newFakeTenantRepo(), newFakeStateRepo(), &fakeAudit{}
	// This helper builds the no-AWS-plumbing service used by B1-compat / local-dev
	// tests, so it opts in to the unprobed all-allowed capability stub explicitly.
	// Deployed wiring never sets this flag and therefore fails closed.
	return NewService(Config{Tenants: tr, State: sr, Audit: au, AllowUnprobedCapabilities: true}), tr, sr, au
}

// newServiceWithRendering constructs a Service with a stub renderer + publisher.
func newServiceWithRendering() (*Service, *fakeTenantRepo, *fakeStateRepo, *fakeAudit, *fakeRenderer, *fakePublisher) {
	tr, sr, au := newFakeTenantRepo(), newFakeStateRepo(), &fakeAudit{}
	r := &fakeRenderer{}
	p := &fakePublisher{}
	return NewService(Config{
		Tenants:           tr,
		State:             sr,
		Audit:             au,
		Renderer:          r,
		Publisher:         p,
		SaaSAccountID:     "111122223333",
		SaaSPrincipalName: "identity-gateway-management-api",
		Region:            "eu-north-1",
	}), tr, sr, au, r, p
}

type fakeRenderer struct {
	lastFormat string
	lastInput  RendererInput
	ret        []byte
	err        error
}

func (f *fakeRenderer) Render(format string, in RendererInput) ([]byte, error) {
	f.lastFormat = format
	f.lastInput = in
	if f.err != nil {
		return nil, f.err
	}
	if f.ret != nil {
		return f.ret, nil
	}
	return []byte("RENDERED-" + format + "-" + in.TenantSlug), nil
}

type fakePublisher struct {
	lastSlug   string
	lastFormat string
	lastBody   []byte
	ret        string
	err        error
}

func (f *fakePublisher) Publish(ctx context.Context, slug, format string, body []byte) (string, error) {
	f.lastSlug = slug
	f.lastFormat = format
	f.lastBody = body
	if f.err != nil {
		return "", f.err
	}
	if f.ret != "" {
		return f.ret, nil
	}
	return "https://example.com/bucket/templates/" + slug + "/abc." + format, nil
}

// --- Tests ---

func TestCreateTenant_CreatesRowAndState(t *testing.T) {
	svc, tr, sr, au := newService()

	state, err := svc.CreateTenant(context.Background(), CreateTenantInput{
		Slug:        "acme",
		DisplayName: "Acme Corp",
		Domain:      "acme.example.com",
		CreatedBy:   "admin@example.com",
	})
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, "acme", state.TenantSlug)
	assert.Equal(t, 1, state.CurrentStep)

	tnt, err := tr.Get(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, "pending", tnt.OnboardingState)
	assert.Equal(t, "Acme Corp", tnt.DisplayName)

	stored, err := sr.Get(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, 1, stored.CurrentStep)

	assert.Equal(t, []string{"onboarding.tenant_created"}, au.events)
}

func TestCreateTenant_RejectsInvalidSlug(t *testing.T) {
	svc, _, _, _ := newService()
	cases := []string{"", "A", "ab", "a b", "acme!", "1abc"}
	for _, slug := range cases {
		_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: slug, DisplayName: "x"})
		require.Errorf(t, err, "slug %q should be rejected", slug)
	}
}

func TestCreateTenant_RejectsDuplicateSlug(t *testing.T) {
	svc, _, _, _ := newService()

	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)

	_, err = svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme 2"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestSetCapabilities_StoresSelection(t *testing.T) {
	svc, _, sr, au := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)

	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core", "user_directory"}))

	got, err := sr.Get(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, []string{"core", "user_directory"}, got.Capabilities)
	assert.Equal(t, 2, got.CurrentStep)

	assert.Contains(t, au.events, "onboarding.capabilities_selected")
}

func TestSetCapabilities_RejectsUnknownPack(t *testing.T) {
	svc, _, _, _ := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)

	err = svc.SetCapabilities(context.Background(), "acme", []string{"core", "ImproperPack"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown capability")
}

func TestSetCapabilities_AlwaysIncludesCore(t *testing.T) {
	svc, _, sr, _ := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)

	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"user_directory"}))

	got, err := sr.Get(context.Background(), "acme")
	require.NoError(t, err)
	assert.Contains(t, got.Capabilities, "core", "core must always be enabled")
	assert.Contains(t, got.Capabilities, "user_directory")
}

func TestSetCapabilities_RejectedAfterIdentityRegistered(t *testing.T) {
	svc, _, sr, _ := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core"}))
	_, err = svc.GenerateIaC(context.Background(), "acme", "cfn")
	require.NoError(t, err)
	require.NoError(t, svc.RegisterIdentity(context.Background(), "acme", RegisterIdentityInput{
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		PoolID:    "eu-north-1_xyz999",
		ClientID:  "client-abc",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		Region:    "eu-north-1",
		Domain:    "acme.auth.eu-north-1.amazoncognito.com",
	}))

	// Now try to re-submit capabilities — must fail.
	err = svc.SetCapabilities(context.Background(), "acme", []string{"core", "user_lifecycle"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot change capabilities after identity is registered")

	// State must remain unchanged.
	got, err := sr.Get(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, 4, got.CurrentStep, "step must not regress")
	assert.Equal(t, []string{"core"}, got.Capabilities, "capabilities must not be mutated")
}

func TestGenerateIaC_PopulatesExternalIDOnFirstCall(t *testing.T) {
	svc, _, sr, au := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core"}))

	artifact, err := svc.GenerateIaC(context.Background(), "acme", "cfn")
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Equal(t, "cfn", artifact.Format)
	got, err := sr.Get(context.Background(), "acme")
	require.NoError(t, err)
	assert.NotEmpty(t, got.ExternalID, "ExternalID must be generated on first IaC call")
	assert.Equal(t, 1, got.IaCVersion)
	assert.Equal(t, 3, got.CurrentStep)
	assert.Contains(t, au.events, "onboarding.iac_generated")
}

func TestGenerateIaC_SameExternalIDAcrossRegenerations(t *testing.T) {
	svc, _, sr, _ := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core"}))

	_, err = svc.GenerateIaC(context.Background(), "acme", "cfn")
	require.NoError(t, err)
	first, _ := sr.Get(context.Background(), "acme")
	firstExt := first.ExternalID

	_, err = svc.GenerateIaC(context.Background(), "acme", "tf")
	require.NoError(t, err)
	second, _ := sr.Get(context.Background(), "acme")

	assert.Equal(t, firstExt, second.ExternalID, "ExternalID is stable — regeneration never rotates it")
	assert.Equal(t, 2, second.IaCVersion, "IaCVersion increments on each regeneration")
}

func TestGenerateIaC_RejectsUnknownFormat(t *testing.T) {
	svc, _, _, _ := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core"}))

	_, err = svc.GenerateIaC(context.Background(), "acme", "toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

func TestRegisterIdentity_WritesFieldsToTenant(t *testing.T) {
	svc, tr, sr, au := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core"}))
	_, err = svc.GenerateIaC(context.Background(), "acme", "cfn")
	require.NoError(t, err)

	err = svc.RegisterIdentity(context.Background(), "acme", RegisterIdentityInput{
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		PoolID:    "eu-north-1_xyz999",
		ClientID:  "client-abc",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		Region:    "eu-north-1",
		Domain:    "acme.auth.eu-north-1.amazoncognito.com",
	})
	require.NoError(t, err)

	got, err := sr.Get(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, 4, got.CurrentStep)
	assert.Contains(t, au.events, "onboarding.identity_registered")

	tnt, _ := tr.Get(context.Background(), "acme")
	assert.Equal(t, "in_progress", tnt.OnboardingState)
}

func TestProbeCapabilities_ReturnsStub(t *testing.T) {
	svc, _, sr, au := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core", "user_directory"}))
	_, err = svc.GenerateIaC(context.Background(), "acme", "cfn")
	require.NoError(t, err)
	err = svc.RegisterIdentity(context.Background(), "acme", RegisterIdentityInput{
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		PoolID:    "eu-north-1_xyz999",
		ClientID:  "client-abc",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		Region:    "eu-north-1",
		Domain:    "acme.auth.eu-north-1.amazoncognito.com",
	})
	require.NoError(t, err)

	result, err := svc.ProbeCapabilities(context.Background(), "acme")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result["core"], "stub assumes core passes")
	assert.True(t, result["user_directory"], "stub assumes user_directory passes")

	got, _ := sr.Get(context.Background(), "acme")
	assert.Equal(t, 5, got.CurrentStep)
	assert.Contains(t, au.events, "onboarding.capabilities_probed")
}

func TestComplete_MarksTenantActiveAndDeletesState(t *testing.T) {
	svc, tr, sr, au := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core"}))
	_, err = svc.GenerateIaC(context.Background(), "acme", "cfn")
	require.NoError(t, err)
	err = svc.RegisterIdentity(context.Background(), "acme", RegisterIdentityInput{
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		PoolID:    "eu-north-1_xyz999",
		ClientID:  "client-abc",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		Region:    "eu-north-1",
		Domain:    "acme.auth.eu-north-1.amazoncognito.com",
	})
	require.NoError(t, err)
	_, err = svc.ProbeCapabilities(context.Background(), "acme")
	require.NoError(t, err)

	require.NoError(t, svc.Complete(context.Background(), "acme"))

	tnt, _ := tr.Get(context.Background(), "acme")
	assert.Equal(t, "active", tnt.OnboardingState, "Complete must mark tenant active")
	assert.Equal(t, map[string]bool{"core": true}, tnt.CapabilityMap, "tenant inherits CapabilityMap from state")

	_, err = sr.Get(context.Background(), "acme")
	assert.Error(t, err, "state row must be deleted on completion")

	assert.Contains(t, au.events, "onboarding.completed")
}

func TestComplete_RequiresProbeFirst(t *testing.T) {
	svc, _, _, _ := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core"}))

	err = svc.Complete(context.Background(), "acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot complete")
}

func TestGetState_ReturnsCurrentStateForResume(t *testing.T) {
	svc, _, _, _ := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core", "user_directory"}))

	state, err := svc.GetState(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, "acme", state.TenantSlug)
	assert.Equal(t, 2, state.CurrentStep)
	assert.Equal(t, []string{"core", "user_directory"}, state.Capabilities)
	assert.Empty(t, state.ExternalID, "ExternalID must not be returned via GetState")
}

func TestGenerateIaC_RendersBytesWhenRendererProvided(t *testing.T) {
	svc, _, _, _, fr, fp := newServiceWithRendering()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core", "user_directory"}))

	art, err := svc.GenerateIaC(context.Background(), "acme", "cfn")
	require.NoError(t, err)
	require.NotNil(t, art)

	assert.Equal(t, "cfn", fr.lastFormat)
	assert.Equal(t, "acme", fr.lastInput.TenantSlug)
	assert.Equal(t, "111122223333", fr.lastInput.SaaSAccountID)
	assert.True(t, fr.lastInput.WantUserDirectory, "user_directory selected → flag true")
	assert.False(t, fr.lastInput.WantUserLifecycle, "user_lifecycle not selected")
	assert.NotEmpty(t, fr.lastInput.ExternalID, "renderer gets the ExternalID")

	assert.Equal(t, "RENDERED-cfn-acme", string(art.Bytes))

	assert.Equal(t, "acme", fp.lastSlug)
	assert.Equal(t, "cfn", fp.lastFormat)
	assert.Equal(t, art.Bytes, fp.lastBody)

	assert.NotEmpty(t, art.DownloadURL)
	assert.Contains(t, art.DownloadURL, "templates/acme/")

	assert.NotEmpty(t, art.QuickCreateURL)
	assert.Contains(t, art.QuickCreateURL, "templateURL=")
	assert.Contains(t, art.QuickCreateURL, "param_ExternalId=")
	assert.Contains(t, art.QuickCreateURL, "stackName=identity-gateway-acme")
}

func TestGenerateIaC_NoQuickCreateForNonCFN(t *testing.T) {
	svc, _, _, _, _, _ := newServiceWithRendering()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core"}))

	art, err := svc.GenerateIaC(context.Background(), "acme", "tf")
	require.NoError(t, err)
	assert.Empty(t, art.QuickCreateURL, "quickCreate is CFN-only")
	assert.NotEmpty(t, art.DownloadURL, "downloadURL still set for tf")
}

func TestGenerateIaC_RendererErrorPropagates(t *testing.T) {
	svc, _, _, _, fr, _ := newServiceWithRendering()
	fr.err = errors.New("template explosion")

	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core"}))

	_, err = svc.GenerateIaC(context.Background(), "acme", "cfn")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template explosion")
}

func TestGenerateIaC_PublisherErrorPropagates(t *testing.T) {
	svc, _, _, _, _, fp := newServiceWithRendering()
	fp.err = errors.New("AccessDenied on bucket")

	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core"}))

	_, err = svc.GenerateIaC(context.Background(), "acme", "cfn")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}

func TestGenerateIaC_B1CompatMode_NoRenderer(t *testing.T) {
	svc, _, sr, _ := newService()
	_, err := svc.CreateTenant(context.Background(), CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(context.Background(), "acme", []string{"core"}))

	art, err := svc.GenerateIaC(context.Background(), "acme", "cfn")
	require.NoError(t, err)
	require.NotNil(t, art)
	assert.NotEmpty(t, art.ExternalID)
	assert.Empty(t, art.Bytes, "no renderer → no bytes")
	assert.Empty(t, art.DownloadURL, "no publisher → no download URL")
	got, _ := sr.Get(context.Background(), "acme")
	assert.Equal(t, 3, got.CurrentStep, "state still advances")
}

type fakeSourceRepo struct {
	items map[string][]*tenant.IdentitySource
}

func newFakeSourceRepo() *fakeSourceRepo {
	return &fakeSourceRepo{items: map[string][]*tenant.IdentitySource{}}
}

func (f *fakeSourceRepo) Get(ctx context.Context, slug, id string) (*tenant.IdentitySource, error) {
	for _, s := range f.items[slug] {
		if s.ID == id {
			cp := *s
			return &cp, nil
		}
	}
	return nil, errors.New("not found")
}

func (f *fakeSourceRepo) List(ctx context.Context, slug string) ([]*tenant.IdentitySource, error) {
	out := make([]*tenant.IdentitySource, 0, len(f.items[slug]))
	for _, s := range f.items[slug] {
		cp := *s
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeSourceRepo) Create(ctx context.Context, slug string, src *tenant.IdentitySource) (string, error) {
	src.ID = fmt.Sprintf("src-%s-%d", slug, len(f.items[slug])+1)
	src.TenantSlug = slug
	cp := *src
	f.items[slug] = append(f.items[slug], &cp)
	return src.ID, nil
}

func (f *fakeSourceRepo) Update(ctx context.Context, slug string, src *tenant.IdentitySource) error {
	list := f.items[slug]
	for i, existing := range list {
		if existing.ID == src.ID {
			cp := *src
			cp.TenantSlug = slug
			list[i] = &cp
			return nil
		}
	}
	return errors.New("not found")
}

func (f *fakeSourceRepo) Delete(ctx context.Context, slug, id string) error {
	list := f.items[slug]
	for i, s := range list {
		if s.ID == id {
			f.items[slug] = append(list[:i], list[i+1:]...)
			return nil
		}
	}
	return errors.New("not found")
}

type fakeProber struct {
	perAction   map[string]bool
	calls       atomic.Int32
	lastArn     string
	lastActions []string
	err         error
}

func (f *fakeProber) Simulate(ctx context.Context, roleArn string, actions []string, resources ...string) (map[string]bool, error) {
	f.calls.Add(1)
	f.lastArn = roleArn
	f.lastActions = actions
	if f.err != nil {
		return nil, f.err
	}
	result := make(map[string]bool, len(actions))
	for _, a := range actions {
		result[a] = f.perAction[a]
	}
	return result, nil
}

type fakeStsAssumer struct {
	calls atomic.Int32
	err   error
}

func (f *fakeStsAssumer) AssumeForTenant(ctx context.Context, src *tenant.IdentitySource) (aws.CredentialsProvider, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return aws.AnonymousCredentials{}, nil
}

func newServiceWithProbing() (*Service, *fakeTenantRepo, *fakeSourceRepo, *fakeStateRepo, *fakeAudit, *fakeProber, *fakeStsAssumer) {
	tr, sr, au := newFakeTenantRepo(), newFakeStateRepo(), &fakeAudit{}
	src := newFakeSourceRepo()
	prober := &fakeProber{}
	assumer := &fakeStsAssumer{}
	svc := NewService(Config{
		Tenants:       tr,
		Sources:       src,
		State:         sr,
		Audit:         au,
		StsAssumer:    assumer,
		ProberFactory: func(creds aws.CredentialsProvider) CapabilityProber { return prober },
	})
	return svc, tr, src, sr, au, prober, assumer
}

func TestProbeCapabilities_RealProbe_AllPacksAllowed(t *testing.T) {
	svc, _, _, _, _, prober, assumer := newServiceWithProbing()
	ctx := context.Background()
	_, err := svc.CreateTenant(ctx, CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(ctx, "acme", []string{"core", "user_directory"}))
	_, err = svc.GenerateIaC(ctx, "acme", "cfn")
	require.NoError(t, err)
	require.NoError(t, svc.RegisterIdentity(ctx, "acme", RegisterIdentityInput{
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		PoolID:    "eu-north-1_xyz999",
		ClientID:  "client-abc",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		Region:    "eu-north-1",
	}))

	prober.perAction = map[string]bool{}
	for _, a := range packActions[PackCore] {
		prober.perAction[a] = true
	}
	// Scoped actions: Core simulates these with ResourceArns.
	prober.perAction["secretsmanager:GetSecretValue"] = true
	prober.perAction["kms:Decrypt"] = true
	for _, a := range packActions[PackUserDirectory] {
		prober.perAction[a] = true
	}

	result, err := svc.ProbeCapabilities(ctx, "acme")
	require.NoError(t, err)

	assert.True(t, result["core"])
	assert.True(t, result["user_directory"])
	assert.Equal(t, int32(1), assumer.calls.Load(), "one AssumeRole call")
}

func TestProbeCapabilities_RealProbe_UserLifecyclePartialDenied(t *testing.T) {
	svc, _, _, _, _, prober, _ := newServiceWithProbing()
	ctx := context.Background()
	_, err := svc.CreateTenant(ctx, CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(ctx, "acme", []string{"core", "user_lifecycle"}))
	_, err = svc.GenerateIaC(ctx, "acme", "cfn")
	require.NoError(t, err)
	require.NoError(t, svc.RegisterIdentity(ctx, "acme", RegisterIdentityInput{
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		PoolID:    "eu-north-1_xyz999",
		ClientID:  "client-abc",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		Region:    "eu-north-1",
	}))

	prober.perAction = map[string]bool{}
	for _, a := range packActions[PackCore] {
		prober.perAction[a] = true
	}
	prober.perAction["secretsmanager:GetSecretValue"] = true
	prober.perAction["kms:Decrypt"] = true
	for _, a := range packActions[PackUserLifecycle] {
		prober.perAction[a] = true
	}
	prober.perAction["cognito-idp:AdminCreateUser"] = false

	result, err := svc.ProbeCapabilities(ctx, "acme")
	require.NoError(t, err)

	assert.True(t, result["core"], "core still passes")
	assert.False(t, result["user_lifecycle"], "one missing action → pack fails")
}

func TestProbeCapabilities_LoadsRegisteredIdentitySource(t *testing.T) {
	svc, _, sources, _, _, _, _ := newServiceWithProbing()
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(ctx, "acme", []string{"core"}))
	_, err = svc.GenerateIaC(ctx, "acme", "cfn")
	require.NoError(t, err)
	require.NoError(t, svc.RegisterIdentity(ctx, "acme", RegisterIdentityInput{
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		PoolID:    "eu-north-1_xyz999",
		ClientID:  "client-abc",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		Region:    "eu-north-1",
	}))

	list, err := sources.List(ctx, "acme")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "arn:aws:iam::123456789012:role/identity-gateway-acme", list[0].RoleArn)
	assert.Equal(t, "eu-north-1_xyz999", list[0].PoolID)
	assert.Equal(t, "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB", list[0].SecretArn)
	assert.NotEmpty(t, list[0].ExternalID, "ExternalID copied from wizard state")
}

func TestProbeCapabilities_AssumeRoleErrorPropagates(t *testing.T) {
	svc, _, _, _, _, _, assumer := newServiceWithProbing()
	assumer.err = errors.New("AccessDenied: trust policy rejected caller")
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(ctx, "acme", []string{"core"}))
	_, err = svc.GenerateIaC(ctx, "acme", "cfn")
	require.NoError(t, err)
	require.NoError(t, svc.RegisterIdentity(ctx, "acme", RegisterIdentityInput{
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		PoolID:    "eu-north-1_xyz999",
		ClientID:  "client-abc",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		Region:    "eu-north-1",
	}))

	_, err = svc.ProbeCapabilities(ctx, "acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}

func TestProbeCapabilities_CoreFailsIfScopedSecretDenied(t *testing.T) {
	// Core must fail when the resource-scoped secretsmanager:GetSecretValue
	// simulation returns denied, even if all unscoped cognito-idp actions are
	// allowed.
	svc, _, _, _, _, prober, _ := newServiceWithProbing()
	ctx := context.Background()
	_, err := svc.CreateTenant(ctx, CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(ctx, "acme", []string{"core"}))
	_, err = svc.GenerateIaC(ctx, "acme", "cfn")
	require.NoError(t, err)
	require.NoError(t, svc.RegisterIdentity(ctx, "acme", RegisterIdentityInput{
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		PoolID:    "eu-north-1_xyz999",
		ClientID:  "client-abc",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		Region:    "eu-north-1",
	}))

	// Unscoped cognito-idp actions all allowed, but resource-scoped secret access denied.
	prober.perAction = map[string]bool{}
	for _, a := range packActions[PackCore] {
		prober.perAction[a] = true
	}
	prober.perAction["secretsmanager:GetSecretValue"] = false
	prober.perAction["kms:Decrypt"] = true

	result, err := svc.ProbeCapabilities(ctx, "acme")
	require.NoError(t, err)
	assert.False(t, result["core"], "core must fail when scoped secret access is denied")
}

func TestProbeCapabilities_B1CompatStubWhenSourcesNil(t *testing.T) {
	// newService() opts in to AllowUnprobedCapabilities, so the all-allowed stub
	// is returned (the local-dev / B1-compat path).
	svc, _, _, _ := newService()
	ctx := context.Background()
	_, err := svc.CreateTenant(ctx, CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(ctx, "acme", []string{"core", "user_directory"}))
	_, err = svc.GenerateIaC(ctx, "acme", "cfn")
	require.NoError(t, err)
	require.NoError(t, svc.RegisterIdentity(ctx, "acme", RegisterIdentityInput{
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		PoolID:    "eu-north-1_xyz999",
		ClientID:  "client-abc",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		Region:    "eu-north-1",
	}))

	result, err := svc.ProbeCapabilities(ctx, "acme")
	require.NoError(t, err)
	assert.True(t, result["core"])
	assert.True(t, result["user_directory"])
}

// TestProbeCapabilities_FailsClosedWhenProberMissing asserts that a service
// built WITHOUT the AWS probe plumbing and WITHOUT the explicit opt-in must not
// return the all-allowed stub — it must error, so a misconfigured deployment can
// never report unverified capabilities as granted.
func TestProbeCapabilities_FailsClosedWhenProberMissing(t *testing.T) {
	tr, sr, au := newFakeTenantRepo(), newFakeStateRepo(), &fakeAudit{}
	// No Sources/StsAssumer/ProberFactory and AllowUnprobedCapabilities left false.
	svc := NewService(Config{Tenants: tr, State: sr, Audit: au})
	ctx := context.Background()
	_, err := svc.CreateTenant(ctx, CreateTenantInput{Slug: "acme", DisplayName: "Acme"})
	require.NoError(t, err)
	require.NoError(t, svc.SetCapabilities(ctx, "acme", []string{"core", "user_directory"}))
	_, err = svc.GenerateIaC(ctx, "acme", "cfn")
	require.NoError(t, err)
	require.NoError(t, svc.RegisterIdentity(ctx, "acme", RegisterIdentityInput{
		RoleArn:   "arn:aws:iam::123456789012:role/identity-gateway-acme",
		PoolID:    "eu-north-1_xyz999",
		ClientID:  "client-abc",
		SecretArn: "arn:aws:secretsmanager:eu-north-1:123456789012:secret:x-AB",
		Region:    "eu-north-1",
	}))

	_, err = svc.ProbeCapabilities(ctx, "acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "capability prober is not configured")
}
