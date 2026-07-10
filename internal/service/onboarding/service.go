package onboarding

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/domain"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

// Step numbers — one per wizard screen.
const (
	stepCreateTenant = 1
	stepCapabilities = 2
	stepIaC          = 3
	stepIdentity     = 4
	stepProbe        = 5
	stepComplete     = 6
)

// Capability pack names. Core is mandatory (always added).
const (
	PackCore          = "core"
	PackUserDirectory = "user_directory"
	PackUserLifecycle = "user_lifecycle"
)

var allowedPacks = map[string]struct{}{
	PackCore:          {},
	PackUserDirectory: {},
	PackUserLifecycle: {},
}

// slugPattern enforces DNS-safe, lowercase tenant slugs.
var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,30}$`)

// allowedFormats is the set of supported IaC output formats.
// A configured Renderer produces the artifact bytes; without one, a placeholder is returned.
var allowedFormats = map[string]struct{}{
	"cfn": {},
	"tf":  {},
	"cli": {},
}

// Renderer renders IaC artifact bytes for a given format. Defined here so
// tests can stub without importing the templates package.
type Renderer interface {
	Render(format string, input RendererInput) ([]byte, error)
}

// RendererInput carries the substitution values; mirrors internal/iac/templates.Input.
// Duplicated here to keep the service package from depending on the templates
// package at the public interface level — the adapter in cmd/management-api
// bridges the two.
type RendererInput struct {
	TenantSlug        string
	ExternalID        string
	SaaSAccountID     string
	SaaSPrincipalName string
	Region            string
	WantUserDirectory bool
	WantUserLifecycle bool
}

// Publisher uploads artifact bytes and returns a public URL.
type Publisher interface {
	Publish(ctx context.Context, slug, format string, body []byte) (string, error)
}

// CapabilityProber evaluates whether a role ARN can perform a list of IAM actions.
// Wired to iam.Prober in production.
type CapabilityProber interface {
	// Simulate evaluates whether roleArn is permitted to perform each action.
	// If resources is non-empty, the simulation is scoped to those ARNs —
	// necessary for resource-restricted policies (e.g. secretsmanager, kms).
	Simulate(ctx context.Context, roleArn string, actions []string, resources ...string) (map[string]bool, error)
}

// StsAssumer builds a credential provider for a tenant's cross-account role.
// Wired to sts.Provider in production.
type StsAssumer interface {
	AssumeForTenant(ctx context.Context, src *tenant.IdentitySource) (aws.CredentialsProvider, error)
}

// ProberFactory constructs a CapabilityProber given an AWS credentials
// provider. The production implementation builds an iam.Client with those
// credentials and wraps it in iam.NewProber.
type ProberFactory func(creds aws.CredentialsProvider) CapabilityProber

type Config struct {
	Tenants   domain.TenantRepository
	Sources   domain.SourceRepository
	State     domain.OnboardingStateRepository
	Audit     domain.AuditRepository
	Renderer  Renderer
	Publisher Publisher
	// Dependencies for the capability probe. Production wiring
	// (cmd/management-api) always supplies all three.
	StsAssumer        StsAssumer
	ProberFactory     ProberFactory
	SaaSAccountID     string
	SaaSPrincipalName string
	Region            string
	// AllowUnprobedCapabilities opts in to the all-allowed capability stub used
	// by unit tests and local dev without AWS creds. It MUST be false in every
	// deployed environment: when it is false and the AWS probe plumbing (Sources,
	// StsAssumer, or ProberFactory) is missing, ProbeCapabilities fails closed
	// with an error rather than reporting every capability as granted.
	// A silent all-true default would let a misconfigured deploy tell a customer
	// their cross-account role has permissions it was never checked for.
	AllowUnprobedCapabilities bool
}

type Service struct {
	tenants                   domain.TenantRepository
	sources                   domain.SourceRepository
	state                     domain.OnboardingStateRepository
	audit                     domain.AuditRepository
	renderer                  Renderer
	publisher                 Publisher
	stsAssumer                StsAssumer
	proberFactory             ProberFactory
	saasAccountID             string
	saasPrincipalName         string
	region                    string
	allowUnprobedCapabilities bool
}

func NewService(cfg Config) *Service {
	return &Service{
		tenants:                   cfg.Tenants,
		sources:                   cfg.Sources,
		state:                     cfg.State,
		audit:                     cfg.Audit,
		renderer:                  cfg.Renderer,
		publisher:                 cfg.Publisher,
		stsAssumer:                cfg.StsAssumer,
		proberFactory:             cfg.ProberFactory,
		saasAccountID:             cfg.SaaSAccountID,
		saasPrincipalName:         cfg.SaaSPrincipalName,
		region:                    cfg.Region,
		allowUnprobedCapabilities: cfg.AllowUnprobedCapabilities,
	}
}

// CreateTenantInput is the argument to CreateTenant.
type CreateTenantInput struct {
	Slug        string
	DisplayName string
	Domain      string
	CreatedBy   string // Cognito sub of the operator running the wizard
}

// CreateTenant handles step 1: create a pending tenant row and initialize wizard state.
//
// Partial-failure note: if the tenant row is created but the state row write
// fails, the tenant row persists in the config table with OnboardingState="pending"
// but no wizard state exists for resume. A subsequent CreateTenant call will
// fail with "already exists". Operator recovery: manually delete the tenant row.
// A future enhancement could add automated recovery (compensating delete or
// get-or-create semantics).
func (s *Service) CreateTenant(ctx context.Context, in CreateTenantInput) (*domain.OnboardingState, error) {
	if !slugPattern.MatchString(in.Slug) {
		return nil, fmt.Errorf("onboarding: invalid slug %q (must match %s)", in.Slug, slugPattern.String())
	}
	if in.DisplayName == "" {
		return nil, fmt.Errorf("onboarding: displayName is required")
	}

	tnt := &tenant.Tenant{
		Slug:             in.Slug,
		DisplayName:      in.DisplayName,
		Domain:           in.Domain,
		Plan:             "standard",
		Status:           "active",
		OnboardingState:  "pending",
		MaxApps:          10,
		MaxAuthsPerMonth: 10000,
	}
	if err := s.tenants.Create(ctx, tnt); err != nil {
		return nil, fmt.Errorf("onboarding: create tenant: %w", err)
	}

	state := &domain.OnboardingState{
		TenantSlug:  in.Slug,
		CurrentStep: stepCreateTenant,
	}
	if err := s.state.Put(ctx, state); err != nil {
		return nil, fmt.Errorf("onboarding: init state: %w", err)
	}

	if err := s.audit.LogStep(ctx, in.Slug, s.flowID(in.Slug), "onboarding.tenant_created", "", in.CreatedBy, map[string]string{
		"tenant": in.Slug,
	}); err != nil {
		slog.Warn("onboarding: audit log step failed (best-effort)", "error", err, "step", "onboarding.tenant_created", "tenant", in.Slug)
	}
	return state, nil
}

// SetCapabilities handles step 2.
func (s *Service) SetCapabilities(ctx context.Context, slug string, packs []string) error {
	state, err := s.state.Get(ctx, slug)
	if err != nil {
		return fmt.Errorf("onboarding: no state for %q (did CreateTenant run?): %w", slug, err)
	}
	// Guard: once the customer has deployed IaC that encodes a capability
	// selection (step 4+), changing capabilities silently would diverge the
	// stored CapabilityMap from what the customer's IAM role actually permits.
	// Force them to restart onboarding instead.
	if state.CurrentStep >= stepIdentity {
		return fmt.Errorf("onboarding: cannot change capabilities after identity is registered (step %d); restart onboarding to select different packs", state.CurrentStep)
	}
	normalized, err := normalizePacks(packs)
	if err != nil {
		return err
	}
	state.Capabilities = normalized
	state.CurrentStep = stepCapabilities
	if err := s.state.Put(ctx, state); err != nil {
		return fmt.Errorf("onboarding: persist capabilities: %w", err)
	}
	if err := s.audit.LogStep(ctx, slug, s.flowID(slug), "onboarding.capabilities_selected", "", "", map[string]string{
		"packs": fmt.Sprintf("%v", normalized),
	}); err != nil {
		slog.Warn("onboarding: audit log step failed (best-effort)", "error", err, "step", "onboarding.capabilities_selected", "tenant", slug)
	}
	return nil
}

// normalizePacks validates pack names and ensures "core" is always included.
func normalizePacks(packs []string) ([]string, error) {
	seen := map[string]struct{}{PackCore: {}}
	for _, p := range packs {
		if _, ok := allowedPacks[p]; !ok {
			return nil, fmt.Errorf("onboarding: unknown capability pack %q", p)
		}
		seen[p] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	out = append(out, PackCore)
	if _, ok := seen[PackUserDirectory]; ok {
		out = append(out, PackUserDirectory)
	}
	if _, ok := seen[PackUserLifecycle]; ok {
		out = append(out, PackUserLifecycle)
	}
	return out, nil
}

// IaCArtifact carries the rendered template and public URLs.
type IaCArtifact struct {
	Format      string
	ExternalID  string
	Bytes       []byte // rendered template (empty if Renderer is nil)
	DownloadURL string // public S3 URL (empty if Publisher is nil)
	// QuickCreateURL is populated only for format=="cfn" when Publisher is available.
	// UI uses this to open the CloudFormation Console with templateURL + NoEcho ExternalId prefilled.
	QuickCreateURL string
}

// GenerateIaC handles step 3. Renders the template bytes and publishes them
// to a public-read S3 prefix so CloudFormation quick-create can fetch the
// template server-side. If Renderer or Publisher is nil the service leaves
// Bytes/DownloadURL/QuickCreateURL empty (still advances the step counter and
// returns ExternalID).
func (s *Service) GenerateIaC(ctx context.Context, slug, format string) (*IaCArtifact, error) {
	if _, ok := allowedFormats[format]; !ok {
		return nil, fmt.Errorf("onboarding: unknown format %q (want cfn, tf, or cli)", format)
	}
	state, err := s.state.Get(ctx, slug)
	if err != nil {
		return nil, err
	}
	if len(state.Capabilities) == 0 {
		return nil, fmt.Errorf("onboarding: capabilities must be set before generating IaC")
	}
	if state.ExternalID == "" {
		ext, err := GenerateExternalID()
		if err != nil {
			return nil, err
		}
		state.ExternalID = ext
	}
	state.IaCVersion++
	state.CurrentStep = stepIaC
	if err := s.state.Put(ctx, state); err != nil {
		return nil, err
	}

	art := &IaCArtifact{
		Format:     format,
		ExternalID: state.ExternalID,
	}

	if s.renderer != nil {
		rendered, err := s.renderer.Render(format, RendererInput{
			TenantSlug:        slug,
			ExternalID:        state.ExternalID,
			SaaSAccountID:     s.saasAccountID,
			SaaSPrincipalName: s.saasPrincipalName,
			Region:            s.region,
			WantUserDirectory: containsPack(state.Capabilities, PackUserDirectory),
			WantUserLifecycle: containsPack(state.Capabilities, PackUserLifecycle),
		})
		if err != nil {
			return nil, fmt.Errorf("onboarding: render IaC: %w", err)
		}
		art.Bytes = rendered

		if s.publisher != nil {
			url, err := s.publisher.Publish(ctx, slug, format, rendered)
			if err != nil {
				return nil, fmt.Errorf("onboarding: publish IaC: %w", err)
			}
			art.DownloadURL = url
			if format == "cfn" {
				art.QuickCreateURL = buildQuickCreateURL(s.region, slug, url, state.ExternalID)
			}
		}
	}

	if err := s.audit.LogStep(ctx, slug, s.flowID(slug), "onboarding.iac_generated", "", "", map[string]string{
		"format":     format,
		"iacVersion": fmt.Sprintf("%d", state.IaCVersion),
	}); err != nil {
		slog.Warn("onboarding: audit log step failed (best-effort)", "error", err, "step", "onboarding.iac_generated", "tenant", slug)
	}
	return art, nil
}

// containsPack returns true if the capability list contains the given pack.
func containsPack(packs []string, target string) bool {
	for _, p := range packs {
		if p == target {
			return true
		}
	}
	return false
}

// buildQuickCreateURL returns the CloudFormation Console "launch stack" URL.
// See docs.aws.amazon.com/AWSCloudFormation for the canonical parameter names.
func buildQuickCreateURL(region, slug, templateURL, externalID string) string {
	return fmt.Sprintf(
		"https://%s.console.aws.amazon.com/cloudformation/home?region=%s#/stacks/quickCreate?templateURL=%s&stackName=identity-gateway-%s&param_ExternalId=%s",
		region, region,
		urlQueryEscape(templateURL),
		slug,
		urlQueryEscape(externalID),
	)
}

// urlQueryEscape escapes a value for use as a URL query-string parameter.
func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}

// RegisterIdentityInput is the argument to RegisterIdentity.
type RegisterIdentityInput struct {
	RoleArn   string
	PoolID    string
	ClientID  string
	SecretArn string
	Region    string
	Domain    string
}

func (s *Service) RegisterIdentity(ctx context.Context, slug string, in RegisterIdentityInput) error {
	state, err := s.state.Get(ctx, slug)
	if err != nil {
		return err
	}
	if state.ExternalID == "" {
		return fmt.Errorf("onboarding: cannot register identity before GenerateIaC")
	}

	// Persist the IdentitySource so ProbeCapabilities can load it.
	// Skip when the Sources store is absent (tests without a store).
	if s.sources != nil {
		src := &tenant.IdentitySource{
			DisplayName: fmt.Sprintf("Primary pool (onboarded %s)", slug),
			Type:        "cognito",
			PoolID:      in.PoolID,
			Region:      in.Region,
			Domain:      in.Domain,
			ClientID:    in.ClientID,
			Status:      "active",
			RoleArn:     in.RoleArn,
			ExternalID:  state.ExternalID,
			SecretArn:   in.SecretArn,
		}
		if _, err := s.sources.Create(ctx, slug, src); err != nil {
			return fmt.Errorf("onboarding: create identity source: %w", err)
		}
	}

	tnt, err := s.tenants.Get(ctx, slug)
	if err != nil {
		return err
	}
	tnt.OnboardingState = "in_progress"
	if err := s.tenants.Update(ctx, tnt); err != nil {
		return err
	}

	state.CurrentStep = stepIdentity
	if err := s.state.Put(ctx, state); err != nil {
		return err
	}

	if err := s.audit.LogStep(ctx, slug, s.flowID(slug), "onboarding.identity_registered", "", "", map[string]string{
		"roleArn": in.RoleArn,
		"poolId":  in.PoolID,
	}); err != nil {
		slog.Warn("onboarding: audit log step failed (best-effort)", "error", err, "step", "onboarding.identity_registered", "tenant", slug)
	}
	return nil
}

// ProbeCapabilities handles step 5. Loads the tenant's IdentitySource (written
// at step 4), assumes the cross-account role, and runs
// iam:SimulatePrincipalPolicy against the pack-specific action lists. Returns
// a map keyed by pack name (e.g. "core" -> true) — NOT by individual action.
//
// If the AWS probe plumbing (sources/stsAssumer/proberFactory) is absent, the
// behaviour depends on AllowUnprobedCapabilities: when explicitly opted in (unit
// tests, local dev without AWS creds) it returns the all-allowed stub; otherwise
// it fails closed rather than silently reporting every capability as granted.
func (s *Service) ProbeCapabilities(ctx context.Context, slug string) (map[string]bool, error) {
	state, err := s.state.Get(ctx, slug)
	if err != nil {
		return nil, err
	}
	if state.CurrentStep < stepIdentity {
		return nil, fmt.Errorf("onboarding: cannot probe before RegisterIdentity")
	}

	// Fail closed when the AWS plumbing is missing, unless the caller has
	// explicitly opted in to the unprobed stub. A deployed wizard that reached
	// this branch is misconfigured; returning all-true would hand the customer a
	// capability report the gateway never actually verified.
	if s.sources == nil || s.stsAssumer == nil || s.proberFactory == nil {
		if !s.allowUnprobedCapabilities {
			return nil, fmt.Errorf("onboarding: cannot probe capabilities for tenant %q — the capability prober is not configured (Sources, StsAssumer, and ProberFactory are required); refusing to report unverified capabilities", slug)
		}
		slog.Warn("onboarding: returning UNPROBED all-allowed capability stub — AllowUnprobedCapabilities is set; this must never happen in a deployed environment", "tenant", slug)
		result := make(map[string]bool, len(state.Capabilities))
		for _, p := range state.Capabilities {
			result[p] = true
		}
		return s.finalizeProbe(ctx, slug, state, result)
	}

	// Real probe path.
	src, err := s.findIdentitySource(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("onboarding: load identity source: %w", err)
	}
	creds, err := s.stsAssumer.AssumeForTenant(ctx, src)
	if err != nil {
		return nil, fmt.Errorf("onboarding: assume tenant role: %w", err)
	}
	prober := s.proberFactory(creds)

	result := make(map[string]bool, len(state.Capabilities))
	for _, pack := range state.Capabilities {
		actions, ok := packActions[pack]
		if !ok {
			result[pack] = false
			continue
		}
		decisions, err := prober.Simulate(ctx, src.RoleArn, actions)
		if err != nil {
			return nil, fmt.Errorf("onboarding: simulate %s: %w", pack, err)
		}
		packPass := allAllowed(decisions, actions)

		// Core also requires resource-scoped actions — simulate each with its
		// specific ResourceArns so a least-privilege customer policy doesn't
		// false-negative.
		if pack == PackCore && packPass {
			for action, resources := range scopedActionsForCore(src) {
				scopedDecisions, err := prober.Simulate(ctx, src.RoleArn, []string{action}, resources...)
				if err != nil {
					return nil, fmt.Errorf("onboarding: simulate %s (scoped %s): %w", pack, action, err)
				}
				if !scopedDecisions[action] {
					packPass = false
					break
				}
			}
		}

		result[pack] = packPass
	}

	return s.finalizeProbe(ctx, slug, state, result)
}

// finalizeProbe writes the capability map to state, advances step counter,
// logs the audit event, and returns the result. Shared between the stub and
// real probe paths.
func (s *Service) finalizeProbe(ctx context.Context, slug string, state *domain.OnboardingState, result map[string]bool) (map[string]bool, error) {
	state.CapabilityMap = result
	state.CurrentStep = stepProbe
	if err := s.state.Put(ctx, state); err != nil {
		return nil, err
	}
	if err := s.audit.LogStep(ctx, slug, s.flowID(slug), "onboarding.capabilities_probed", "", "", map[string]string{
		"capabilities": fmt.Sprintf("%v", result),
	}); err != nil {
		slog.Warn("onboarding: audit log step failed (best-effort)", "error", err, "step", "onboarding.capabilities_probed", "tenant", slug)
	}
	return result, nil
}

// findIdentitySource loads the first IdentitySource for the tenant. Step 4
// writes exactly one during onboarding; the List→take-first semantics handle
// that case cleanly.
func (s *Service) findIdentitySource(ctx context.Context, slug string) (*tenant.IdentitySource, error) {
	sources, err := s.sources.List(ctx, slug)
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no identity sources for tenant %q (RegisterIdentity must run before probe)", slug)
	}
	return sources[0], nil
}

// allAllowed returns true if every action in `actions` has an entry in
// `decisions` with value true. Missing actions count as false.
func allAllowed(decisions map[string]bool, actions []string) bool {
	for _, a := range actions {
		if !decisions[a] {
			return false
		}
	}
	return true
}

// packActions lists the IAM actions each capability pack requires.
// Actions whose IAM statements are typically scoped to specific resource ARNs
// (and therefore fail simulation against implicit "*") live in packActionsScoped
// and are simulated with explicit ResourceArns.
// Must stay in lockstep with internal/iac/templates/cfn.yaml.tmpl and tf.hcl.tmpl.
var packActions = map[string][]string{
	PackCore: {
		"cognito-idp:DescribeUserPool",
		"cognito-idp:DescribeUserPoolClient",
		"cognito-idp:DescribeUserPoolDomain",
		"cognito-idp:ListIdentityProviders",
	},
	PackUserDirectory: {
		"cognito-idp:ListUsers",
		"cognito-idp:AdminGetUser",
		"cognito-idp:ListGroups",
		"cognito-idp:ListUsersInGroup",
		"cognito-idp:AdminListGroupsForUser",
	},
	PackUserLifecycle: {
		"cognito-idp:AdminCreateUser",
		"cognito-idp:AdminDisableUser",
		"cognito-idp:AdminEnableUser",
		"cognito-idp:AdminAddUserToGroup",
		"cognito-idp:AdminRemoveUserFromGroup",
		"cognito-idp:AdminResetUserPassword",
		"cognito-idp:CreateGroup",
	},
}

// scopedActionsForCore returns the (action → resource-ARN) pairs that Core
// additionally requires beyond packActions[PackCore]. Each is simulated with
// its specific resource so a resource-scoped customer policy doesn't false-
// negative. src carries the SecretArn; the KMS key ARN is not yet tracked on
// IdentitySource — pass "*" for the KMS simulation until we start persisting
// it in step 4 (future refinement).
func scopedActionsForCore(src *tenant.IdentitySource) map[string][]string {
	return map[string][]string{
		"secretsmanager:GetSecretValue": {src.SecretArn},
		"kms:Decrypt":                   {"*"}, // KMS ARN not yet captured at step 4
	}
}

// Complete handles step 6: promote the tenant to active and delete state.
func (s *Service) Complete(ctx context.Context, slug string) error {
	state, err := s.state.Get(ctx, slug)
	if err != nil {
		return err
	}
	if state.CurrentStep < stepProbe {
		return fmt.Errorf("onboarding: cannot complete from step %d (need %d)", state.CurrentStep, stepProbe)
	}
	tnt, err := s.tenants.Get(ctx, slug)
	if err != nil {
		return err
	}
	tnt.OnboardingState = "active"
	tnt.CapabilityMap = state.CapabilityMap
	if err := s.tenants.Update(ctx, tnt); err != nil {
		return err
	}
	if err := s.state.Delete(ctx, slug); err != nil {
		return err
	}
	if err := s.audit.LogStep(ctx, slug, s.flowID(slug), "onboarding.completed", "", "", map[string]string{
		"tenant": slug,
	}); err != nil {
		slog.Warn("onboarding: audit log step failed (best-effort)", "error", err, "step", "onboarding.completed", "tenant", slug)
	}
	return nil
}

// GetState returns the current wizard state for resume. The ExternalID is
// zeroed on the returned copy — it is a long-term trust-policy value and
// should be retrieved only by GenerateIaC (which re-renders it into the IaC).
func (s *Service) GetState(ctx context.Context, slug string) (*domain.OnboardingState, error) {
	state, err := s.state.Get(ctx, slug)
	if err != nil {
		return nil, err
	}
	state.ExternalID = ""
	return state, nil
}

// flowID is a deterministic flow identifier for audit grouping — one flow per
// wizard session (i.e., per tenant onboarding). Multiple regenerations share
// the same flow so the audit timeline groups them.
func (s *Service) flowID(slug string) string {
	return "onboarding-" + slug
}
