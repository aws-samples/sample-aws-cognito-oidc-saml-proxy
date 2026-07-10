package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// authRequestItem is the DynamoDB wrapper for AuthRequest.
type authRequestItem struct {
	PK  string `dynamo:"PK,hash" json:"-"`
	SK  string `dynamo:"SK,range" json:"-"`
	TTL int64  `dynamo:"ttl" json:"-"` // DynamoDB TTL — auto-delete expired requests
	AuthRequest
}

// accessTokenItem stores opaque access tokens in DynamoDB.
type accessTokenItem struct {
	PK        string    `dynamo:"PK,hash" json:"-"`
	SK        string    `dynamo:"SK,range" json:"-"`
	TTL       int64     `dynamo:"ttl" json:"-"` // DynamoDB TTL
	TokenID   string    `dynamo:"tokenID" json:"tokenID"`
	Subject   string    `dynamo:"subject" json:"subject"`
	Audience  []string  `dynamo:"audience" json:"audience"`
	Scopes    []string  `dynamo:"scopes" json:"scopes"`
	ClientID  string    `dynamo:"clientID" json:"clientID"`
	ExpiresAt time.Time `dynamo:"expiresAt" json:"expiresAt"`
}

// Token-type discriminators stored on a sessionTokenIndexItem so TerminateSession
// knows which PK helper to use when deleting the referenced token.
const (
	sessionTokenTypeAccess  = "access"
	sessionTokenTypeRefresh = "refresh"
)

// sessionTokenIndexItem is a secondary index row that maps a user session,
// scoped to (tenant, subject, clientID), to an outstanding token. Access and
// refresh tokens are partitioned by their own opaque values (there is no
// per-user index on the token records themselves), so RP-initiated logout has
// nothing to sweep without this. One index row is written per issued token; the
// row carries the reference needed to rebuild the token's own PK.
type sessionTokenIndexItem struct {
	PK        string `dynamo:"PK,hash" json:"-"`
	SK        string `dynamo:"SK,range" json:"-"`
	TTL       int64  `dynamo:"ttl" json:"-"` // DynamoDB TTL — mirrors the referenced token's grace TTL
	TokenType string `dynamo:"tokenType" json:"tokenType"`
	TokenRef  string `dynamo:"tokenRef" json:"tokenRef"`
}

// userClaims holds Cognito claims for a user session.
type userClaims struct {
	Email      string
	GivenName  string
	FamilyName string
	Groups     []string
	// EmailVerified carries Cognito's real email_verified claim. It MUST reflect
	// the value asserted by the upstream pool — never a hard-coded true.
	// Relying parties use email_verified to decide whether to trust the address
	// (e.g. for account matching), so emitting true for an unverified address is
	// an account-takeover primitive. The zero value (false) is the safe default:
	// an absent or non-boolean upstream claim leaves this false.
	EmailVerified bool
}

// Storage implements op.Storage for the Identity Federation Gateway.
// It delegates to existing stores for application/tenant data and uses
// DynamoDB (via TableAPI) for transient OIDC state (auth requests, tokens).
type Storage struct {
	appStore    *store.AppStore
	claimStore  *store.ClaimStore
	sourceStore *store.SourceStore
	joseSigner  *crypto.KMSJoseSigner
	db          store.TableAPI
	keyID       string
	extraKeys   []op.Key // additional public keys advertised in JWKS (e.g. backup key during a roll)
	userClaims  sync.Map // map[claimsKey(tenant,sub)]*userClaims — tenant-scoped to prevent cross-tenant claim contamination
}

// NewStorage creates a new OIDC Storage.
func NewStorage(
	appStore *store.AppStore,
	claimStore *store.ClaimStore,
	sourceStore *store.SourceStore,
	joseSigner *crypto.KMSJoseSigner,
	db store.TableAPI,
	keyID string,
) *Storage {
	return &Storage{
		appStore:    appStore,
		claimStore:  claimStore,
		sourceStore: sourceStore,
		joseSigner:  joseSigner,
		db:          db,
		keyID:       keyID,
	}
}

// DynamoDB key helpers for OIDC items.
// Each item gets its own partition key to avoid hot partitions under load.
func oidcAuthRequestPK(id string) string { return fmt.Sprintf("AUTHREQ#%s", id) }
func oidcAuthRequestSK() string          { return "META" }
func oidcAuthCodePK(code string) string  { return fmt.Sprintf("AUTHCODE#%s", code) }
func oidcAuthCodeSK() string             { return "META" }
func oidcAccessTokenPK(id string) string { return fmt.Sprintf("TOKEN#%s", id) }
func oidcAccessTokenSK() string          { return "META" }

// oidcSessionIndexPK partitions the session→token index by (tenant, subject,
// clientID). All tokens issued to one client for one user in one tenant share
// this partition, so TerminateSession can Query them with a single lookup. The
// tenant slug (from the request issuer) namespaces the entry to prevent a
// cross-tenant sweep when a subject value collides across tenants; the SK holds
// the token's own opaque value to keep rows unique within the partition.
func oidcSessionIndexPK(tenant, subject, clientID string) string {
	return fmt.Sprintf("OIDCSESSION#t:%s#u:%s#c:%s", tenant, subject, clientID)
}
func oidcSessionIndexSK(tokenRef string) string { return fmt.Sprintf("TOKEN#%s", tokenRef) }

// claimsKey composes the in-memory userClaims cache key from the tenant slug and
// the Cognito subject. Keying on the bare sub alone lets a subject value that
// collides across tenants read another tenant's cached claims; the tenant
// slug (derived from the request issuer) namespaces the entry. An empty tenant is
// kept distinct from any real slug so it can never alias a tenant-scoped entry.
func claimsKey(tenant, sub string) string {
	return "t:" + tenant + "#u:" + sub
}

func generateOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ---------- AuthStorage ----------

// tenantSlugFromIssuer extracts the tenant slug from a zitadel/oidc issuer URL.
// The issuer has the form: baseURL + /t/{tenant}/oidc
func tenantSlugFromIssuer(issuer string) string {
	const marker = "/t/"
	idx := strings.LastIndex(issuer, marker)
	if idx == -1 {
		return ""
	}
	rest := issuer[idx+len(marker):]
	if end := strings.Index(rest, "/"); end != -1 {
		return rest[:end]
	}
	return rest
}

// CreateAuthRequest persists a new authorization request.
func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	id, err := generateOpaqueToken()
	if err != nil {
		return nil, err
	}

	// Extract tenant slug from the issuer in the context.
	// The issuer is set by zitadel/oidc's IssuerInterceptor middleware and has
	// the form: baseURL + /t/{tenant}/oidc
	tenantSlug := tenantSlugFromIssuer(op.IssuerFromContext(ctx))

	authReq := &AuthRequest{
		ID:           id,
		ClientID:     req.ClientID,
		RedirectURI:  req.RedirectURI,
		Scopes:       req.Scopes,
		State:        req.State,
		Nonce:        req.Nonce,
		ResponseType: req.ResponseType,
		TenantSlug:   tenantSlug,
		CreatedAt:    time.Now(),
	}

	if req.CodeChallenge != "" {
		authReq.CodeChallengeValue = req.CodeChallenge
		authReq.CodeChallengeMethod = string(req.CodeChallengeMethod)
		authReq.CodeChallenge = &oidc.CodeChallenge{
			Challenge: req.CodeChallenge,
			Method:    req.CodeChallengeMethod,
		}
	}

	item := authRequestItem{
		PK:          oidcAuthRequestPK(id),
		SK:          oidcAuthRequestSK(),
		TTL:         time.Now().Add(10 * time.Minute).Unix(), // Auto-delete after 10 minutes
		AuthRequest: *authReq,
	}
	if err := s.db.Put(ctx, &item); err != nil {
		return nil, fmt.Errorf("failed to save auth request: %w", err)
	}

	return authReq, nil
}

// AuthRequestByID retrieves an authorization request by its ID.
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	var item authRequestItem
	if err := s.db.Get(ctx, oidcAuthRequestPK(id), oidcAuthRequestSK(), &item); err != nil {
		return nil, fmt.Errorf("auth request %q not found: %w", id, err)
	}

	// Reconstruct CodeChallenge pointer from stored fields
	if item.CodeChallengeValue != "" {
		item.CodeChallenge = &oidc.CodeChallenge{
			Challenge: item.CodeChallengeValue,
			Method:    oidc.CodeChallengeMethod(item.CodeChallengeMethod),
		}
	}

	return &item.AuthRequest, nil
}

// AuthRequestByCode retrieves an authorization request by its authorization code.
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	// Look up the auth request ID from the code mapping
	type codeMapping struct {
		PK        string `dynamo:"PK,hash" json:"-"`
		SK        string `dynamo:"SK,range" json:"-"`
		RequestID string `dynamo:"requestID" json:"requestID"`
	}

	var mapping codeMapping
	if err := s.db.Get(ctx, oidcAuthCodePK(code), oidcAuthCodeSK(), &mapping); err != nil {
		return nil, fmt.Errorf("auth code %q not found: %w", code, err)
	}

	return s.AuthRequestByID(ctx, mapping.RequestID)
}

// SaveAuthCode saves a code-to-request mapping.
func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	type codeMapping struct {
		PK        string `dynamo:"PK,hash" json:"-"`
		SK        string `dynamo:"SK,range" json:"-"`
		TTL       int64  `dynamo:"ttl" json:"-"` // DynamoDB TTL — auto-delete after 10 minutes
		RequestID string `dynamo:"requestID" json:"requestID"`
	}

	item := codeMapping{
		PK:        oidcAuthCodePK(code),
		SK:        oidcAuthCodeSK(),
		TTL:       time.Now().Add(10 * time.Minute).Unix(), // Auth codes are short-lived
		RequestID: id,
	}
	if err := s.db.Put(ctx, &item); err != nil {
		return fmt.Errorf("failed to save auth code: %w", err)
	}

	// Also store the code on the auth request itself
	var reqItem authRequestItem
	if err := s.db.Get(ctx, oidcAuthRequestPK(id), oidcAuthRequestSK(), &reqItem); err == nil {
		reqItem.AuthCode = code
		reqItem.PK = oidcAuthRequestPK(id)
		reqItem.SK = oidcAuthRequestSK()
		_ = s.db.Put(ctx, &reqItem)
	}

	return nil
}

// CompleteAuthRequest marks an authorization request as done with the given user ID.
// This is called after the user successfully authenticates via Cognito.
//
// emailVerified is Cognito's real email_verified claim for this login.
// It is persisted and propagated verbatim so the ID token, userinfo, and
// introspection responses reflect the upstream pool's assertion rather than an
// unconditional true.
func (s *Storage) CompleteAuthRequest(ctx context.Context, id, userID, email, givenName, familyName string, emailVerified bool, groups []string) error {
	var item authRequestItem
	if err := s.db.Get(ctx, oidcAuthRequestPK(id), oidcAuthRequestSK(), &item); err != nil {
		return fmt.Errorf("auth request %q not found: %w", id, err)
	}
	item.UserID = userID
	item.IsDone = true
	item.AuthTime = time.Now()
	item.CognitoEmail = email
	item.CognitoGivenName = givenName
	item.CognitoFamilyName = familyName
	item.CognitoEmailVerified = emailVerified
	item.CognitoGroups = groups
	item.PK = oidcAuthRequestPK(id)
	item.SK = oidcAuthRequestSK()
	if err := s.db.Put(ctx, &item); err != nil {
		return fmt.Errorf("failed to complete auth request: %w", err)
	}

	// Store claims in the user claims cache for quick lookup during token/userinfo
	// requests. The cache is keyed by (tenant, sub) so a subject that collides
	// across tenants cannot read another tenant's claims. The tenant comes
	// from the auth request itself, which recorded the issuer's tenant at creation.
	s.userClaims.Store(claimsKey(item.TenantSlug, userID), &userClaims{
		Email:         email,
		GivenName:     givenName,
		FamilyName:    familyName,
		EmailVerified: emailVerified,
		Groups:        groups,
	})

	return nil
}

// DeleteAuthRequest removes an authorization request.
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	// First try to delete any associated auth code
	var reqItem authRequestItem
	if err := s.db.Get(ctx, oidcAuthRequestPK(id), oidcAuthRequestSK(), &reqItem); err == nil {
		if reqItem.AuthCode != "" {
			_ = s.db.Delete(ctx, oidcAuthCodePK(reqItem.AuthCode), oidcAuthCodeSK())
		}
	}

	return s.db.Delete(ctx, oidcAuthRequestPK(id), oidcAuthRequestSK())
}

// CreateAccessToken creates an opaque access token and stores it.
func (s *Storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	tokenID, err := generateOpaqueToken()
	if err != nil {
		return "", time.Time{}, err
	}

	expiration := time.Now().Add(1 * time.Hour)

	// Extract ClientID from the request. Both the authorization-code
	// (*AuthRequest) and refresh-token (*refreshTokenRequest) paths expose it.
	var clientID string
	if cg, ok := req.(interface{ GetClientID() string }); ok {
		clientID = cg.GetClientID()
	}

	accessTTL := expiration.Add(1 * time.Hour).Unix() // Auto-delete 1h after expiry
	item := accessTokenItem{
		PK:        oidcAccessTokenPK(tokenID),
		SK:        oidcAccessTokenSK(),
		TTL:       accessTTL,
		TokenID:   tokenID,
		Subject:   req.GetSubject(),
		Audience:  req.GetAudience(),
		Scopes:    req.GetScopes(),
		ClientID:  clientID,
		ExpiresAt: expiration,
	}

	if err := s.db.Put(ctx, &item); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to store access token: %w", err)
	}

	// Index the access token under the user's session so RP-initiated logout
	// (TerminateSession) can revoke it. Best-effort: the token is already valid,
	// and TerminateSession also sweeps refresh tokens, so an index-write failure
	// must not fail token issuance.
	s.indexSessionToken(ctx, req.GetSubject(), clientID, sessionTokenTypeAccess, tokenID, accessTTL)

	return tokenID, expiration, nil
}

// CreateAccessAndRefreshTokens creates an access token and a rotating refresh
// token. It is called by zitadel/oidc both on the initial authorization-code
// exchange (when the client holds the refresh_token grant and requested the
// offline_access scope) and on every refresh_token grant (rotation). On
// rotation, currentRefreshToken is the presented token, which is revoked
// (single-use) after the new pair is minted.
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	accessTokenID, expiration, err := s.CreateAccessToken(ctx, req)
	if err != nil {
		return "", "", time.Time{}, err
	}

	rr, ok := req.(refreshableRequest)
	if !ok {
		return "", "", time.Time{}, fmt.Errorf("unsupported token request type %T for refresh token issuance", req)
	}

	refreshToken, err := generateOpaqueToken()
	if err != nil {
		return "", "", time.Time{}, err
	}

	claims := claimsFromRequest(rr)
	lifetime := s.refreshTokenLifetime(ctx, rr.GetClientID())
	refreshExpiry := time.Now().Add(lifetime)

	item := refreshTokenItem{
		PK:            oidcRefreshTokenPK(refreshToken),
		SK:            oidcRefreshTokenSK(),
		TTL:           refreshExpiry.Add(1 * time.Hour).Unix(), // grace before DynamoDB TTL sweep
		Token:         refreshToken,
		Subject:       rr.GetSubject(),
		ClientID:      rr.GetClientID(),
		Audience:      rr.GetAudience(),
		Scopes:        rr.GetScopes(),
		AMR:           rr.GetAMR(),
		AuthTime:      rr.GetAuthTime(),
		ExpiresAt:     refreshExpiry,
		Email:         claims.Email,
		GivenName:     claims.GivenName,
		FamilyName:    claims.FamilyName,
		EmailVerified: claims.EmailVerified,
		Groups:        claims.Groups,
	}
	if err := s.db.Put(ctx, &item); err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Index the refresh token under the user's session so RP-initiated logout
	// (TerminateSession) can revoke it — this is the token that would otherwise
	// keep minting access tokens for up to 30 days after a cosmetic logout.
	s.indexSessionToken(ctx, rr.GetSubject(), rr.GetClientID(), sessionTokenTypeRefresh, refreshToken, item.TTL)

	// Rotation: revoke the presented refresh token so it cannot be replayed, and
	// drop its now-stale session-index row so a later logout sweep does not chase
	// a deleted token.
	if currentRefreshToken != "" && currentRefreshToken != refreshToken {
		_ = s.db.Delete(ctx, oidcRefreshTokenPK(currentRefreshToken), oidcRefreshTokenSK())
		s.deleteSessionTokenIndex(ctx, rr.GetSubject(), rr.GetClientID(), currentRefreshToken)
	}

	return accessTokenID, refreshToken, expiration, nil
}

// refreshTokenLifetime resolves the refresh-token lifetime for a client,
// preferring a per-client OIDCConfig override and falling back to the gateway
// default. Lookup failures are non-fatal — they just yield the default.
func (s *Storage) refreshTokenLifetime(ctx context.Context, clientID string) time.Duration {
	if clientID == "" {
		return defaultRefreshTokenLifetime
	}
	_, _, oidcCfg, err := s.appStore.GetByClientID(ctx, clientID)
	if err == nil && oidcCfg != nil && oidcCfg.RefreshTokenLifetimeSec > 0 {
		return time.Duration(oidcCfg.RefreshTokenLifetimeSec) * time.Second
	}
	return defaultRefreshTokenLifetime
}

// TokenRequestByRefreshToken looks up the original authorization context for a
// refresh token. Returns op.ErrInvalidRefreshToken when the token is unknown or
// expired so zitadel/oidc can surface an invalid_grant error.
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	var item refreshTokenItem
	if err := s.db.Get(ctx, oidcRefreshTokenPK(refreshToken), oidcRefreshTokenSK(), &item); err != nil {
		return nil, op.ErrInvalidRefreshToken
	}

	// Defensive expiry check in addition to the DynamoDB TTL, which is
	// best-effort and can lag by up to 48h.
	if !item.ExpiresAt.IsZero() && time.Now().After(item.ExpiresAt) {
		_ = s.db.Delete(ctx, oidcRefreshTokenPK(refreshToken), oidcRefreshTokenSK())
		return nil, op.ErrInvalidRefreshToken
	}

	// Repopulate the in-memory claims cache so the re-issued ID token and
	// userinfo response carry the same claims as the original login. This
	// matters across Lambda invocations where the cache starts empty. The cache
	// is keyed by (tenant, sub) to keep tenants isolated; the tenant is
	// derived from the request issuer, which is present on the token endpoint.
	claims := userClaims{
		Email:         item.Email,
		GivenName:     item.GivenName,
		FamilyName:    item.FamilyName,
		EmailVerified: item.EmailVerified,
		Groups:        item.Groups,
	}
	tenantSlug := tenantSlugFromIssuer(op.IssuerFromContext(ctx))
	s.userClaims.Store(claimsKey(tenantSlug, item.Subject), &claims)

	return &refreshTokenRequest{
		clientID: item.ClientID,
		subject:  item.Subject,
		audience: item.Audience,
		scopes:   item.Scopes,
		amr:      item.AMR,
		authTime: item.AuthTime,
		claims:   claims,
	}, nil
}

// indexSessionToken records a session→token index row so TerminateSession can
// later revoke the token. The tenant is derived from the request issuer (the
// end_session and token endpoints both run behind the IssuerInterceptor), which
// scopes the sweep and keeps colliding subjects across tenants isolated. Writes
// are best-effort: the referenced token is already persisted and valid, so an
// index-write failure must never fail token issuance — at worst that one token
// falls back to expiring via its TTL.
func (s *Storage) indexSessionToken(ctx context.Context, subject, clientID, tokenType, tokenRef string, ttl int64) {
	if subject == "" || clientID == "" || tokenRef == "" {
		return
	}
	tenantSlug := tenantSlugFromIssuer(op.IssuerFromContext(ctx))
	_ = s.db.Put(ctx, &sessionTokenIndexItem{
		PK:        oidcSessionIndexPK(tenantSlug, subject, clientID),
		SK:        oidcSessionIndexSK(tokenRef),
		TTL:       ttl,
		TokenType: tokenType,
		TokenRef:  tokenRef,
	})
}

// deleteSessionTokenIndex removes a single session→token index row, used when a
// token is rotated or revoked so a later logout sweep does not chase a token
// that is already gone. Best-effort, tenant-scoped like indexSessionToken.
func (s *Storage) deleteSessionTokenIndex(ctx context.Context, subject, clientID, tokenRef string) {
	if subject == "" || clientID == "" || tokenRef == "" {
		return
	}
	tenantSlug := tenantSlugFromIssuer(op.IssuerFromContext(ctx))
	_ = s.db.Delete(ctx, oidcSessionIndexPK(tenantSlug, subject, clientID), oidcSessionIndexSK(tokenRef))
}

// TerminateSession terminates a user's session on RP-initiated logout
// (OIDC end_session). zitadel/oidc calls this with the (userID, clientID) of
// the ending session. It sweeps the session→token index for (tenant, userID,
// clientID) and deletes every outstanding access and refresh token, so a
// completed logout actually revokes the credentials rather than leaving a
// refresh token valid for up to its 30-day lifetime. Without this the endpoint
// is cosmetic (MF-4).
func (s *Storage) TerminateSession(ctx context.Context, userID, clientID string) error {
	if userID == "" || clientID == "" {
		return nil
	}
	tenantSlug := tenantSlugFromIssuer(op.IssuerFromContext(ctx))
	indexPK := oidcSessionIndexPK(tenantSlug, userID, clientID)

	var rows []sessionTokenIndexItem
	if err := s.db.Query(ctx, indexPK, oidcSessionIndexSK(""), &rows); err != nil {
		return fmt.Errorf("failed to query session tokens for logout: %w", err)
	}

	for _, row := range rows {
		switch row.TokenType {
		case sessionTokenTypeRefresh:
			_ = s.db.Delete(ctx, oidcRefreshTokenPK(row.TokenRef), oidcRefreshTokenSK())
		case sessionTokenTypeAccess:
			_ = s.db.Delete(ctx, oidcAccessTokenPK(row.TokenRef), oidcAccessTokenSK())
		}
		// Drop the index row itself so a repeated logout is a cheap no-op.
		_ = s.db.Delete(ctx, indexPK, oidcSessionIndexSK(row.TokenRef))
	}

	return nil
}

// RevokeToken revokes an access or refresh token. zitadel/oidc calls this with
// either an access-token ID (resolved from the encrypted bearer) or, for the
// refresh-token hint path, the refresh-token value returned by
// GetRefreshTokenInfo. We attempt both deletes so a single implementation
// covers both token types.
func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID, userID, clientID string) *oidc.Error {
	// RFC 7009 §2.1: the authorization server MUST verify that the token was
	// issued to the client making the revocation request. Load the record and
	// only delete it when the owning client matches. A token belonging to a
	// different client is treated as already-invalid (return nil without
	// deleting it) so one client cannot revoke another client's tokens.
	var access accessTokenItem
	if err := s.db.Get(ctx, oidcAccessTokenPK(tokenOrTokenID), oidcAccessTokenSK(), &access); err == nil {
		if clientID != "" && access.ClientID != "" && access.ClientID != clientID {
			return nil
		}
		if err := s.db.Delete(ctx, oidcAccessTokenPK(tokenOrTokenID), oidcAccessTokenSK()); err != nil {
			return oidc.ErrServerError().WithParent(err)
		}
		return nil
	}

	var refresh refreshTokenItem
	if err := s.db.Get(ctx, oidcRefreshTokenPK(tokenOrTokenID), oidcRefreshTokenSK(), &refresh); err == nil {
		if clientID != "" && refresh.ClientID != "" && refresh.ClientID != clientID {
			return nil
		}
		if err := s.db.Delete(ctx, oidcRefreshTokenPK(tokenOrTokenID), oidcRefreshTokenSK()); err != nil {
			return oidc.ErrServerError().WithParent(err)
		}
		return nil
	}

	// Token unknown (already expired/revoked). RFC 7009 §2.2: respond as success.
	return nil
}

// GetRefreshTokenInfo returns the subject and token value for a refresh token,
// used by the /revoke endpoint. Returns op.ErrInvalidRefreshToken when the
// token is not a valid refresh token so revocation can fall back to treating
// the value as an access token.
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (userID string, tokenID string, err error) {
	var item refreshTokenItem
	if getErr := s.db.Get(ctx, oidcRefreshTokenPK(token), oidcRefreshTokenSK(), &item); getErr != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	if clientID != "" && item.ClientID != "" && item.ClientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	// Return the token value itself as the identifier so RevokeToken can key
	// its delete on it.
	return item.Subject, token, nil
}

// ---------- Signing ----------

// SigningKey returns the KMS-backed signing key for JWT creation.
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return &signingKey{
		id:     s.keyID,
		signer: s.joseSigner,
	}, nil
}

// SignatureAlgorithms returns the supported signing algorithms.
func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet returns the public keys for the JWKS endpoint. It includes the active
// signing key plus any additional verification keys (e.g. the backup key) so
// relying parties can validate tokens signed by either key across a key roll.
func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	jwk := s.joseSigner.Public()
	keys := []op.Key{
		&publicKey{
			id:  s.keyID,
			jwk: jwk,
		},
	}
	keys = append(keys, s.extraKeys...)
	return keys, nil
}

// AddVerificationKey registers an additional public key to advertise in the JWKS
// endpoint without using it for signing. Used to publish the backup signing key
// alongside the active one so a backup promotion does not invalidate
// already-issued tokens. No-op if keyID matches the active signing key.
func (s *Storage) AddVerificationKey(keyID string, jwk *jose.JSONWebKey) {
	if keyID == "" || keyID == s.keyID || jwk == nil {
		return
	}
	s.extraKeys = append(s.extraKeys, &publicKey{id: keyID, jwk: jwk})
}

// ---------- OPStorage ----------

// GetClientByClientID loads a Client from the app store.
// The clientID corresponds to the Application ID in the tenant model.
// Uses the GSI with CLIENTID# prefix for O(1) lookup instead of a table scan.
//
// The gateway is tenant-per-path (issuer = baseURL + /t/{tenant}/oidc), so the
// resolved client MUST belong to the tenant on the request's issuer. Without
// this check a client credential valid for tenant A would be honored on tenant
// B's issuer, defeating the routing scheme's isolation. When the issuer
// carries a tenant and it does not match the client's owning tenant, the client
// is treated as not found — fail closed rather than leak across tenants.
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	tenantSlug, app, oidcCfg, err := s.appStore.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client %q not found: %w", clientID, err)
	}

	if issuerTenant := tenantSlugFromIssuer(op.IssuerFromContext(ctx)); issuerTenant != "" && issuerTenant != tenantSlug {
		return nil, fmt.Errorf("client %q not found in tenant %q", clientID, issuerTenant)
	}

	return NewClient(app, oidcCfg), nil
}

// AuthorizeClientIDSecret validates client credentials.
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	client, err := s.GetClientByClientID(ctx, clientID)
	if err != nil {
		return err
	}

	// If the client uses "none" auth method, no secret is needed
	if client.AuthMethod() == oidc.AuthMethodNone {
		return nil
	}

	// Load the OIDC config to check the secret
	oidcClient, ok := client.(*Client)
	if !ok {
		return fmt.Errorf("unexpected client type")
	}
	if oidcClient.oidcCfg == nil {
		return fmt.Errorf("client %q has no OIDC configuration", clientID)
	}
	// A confidential client (client_secret_basic / client_secret_post) MUST have a
	// stored secret. Without this guard an empty stored secret makes
	// ConstantTimeCompare("", "") == 1, so anyone presenting an empty secret would
	// authenticate as the client. Only AuthMethodNone (public + PKCE,
	// handled above) may authenticate without a secret; fail closed here.
	if oidcClient.oidcCfg.ClientSecret == "" {
		return fmt.Errorf("client %q has no configured secret for auth method %q", clientID, client.AuthMethod())
	}
	if subtle.ConstantTimeCompare([]byte(oidcClient.oidcCfg.ClientSecret), []byte(clientSecret)) != 1 {
		return fmt.Errorf("invalid client secret")
	}

	return nil
}

// SetUserinfoFromScopes populates userinfo from scopes (deprecated in favor of SetUserinfoFromRequest).
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	userinfo.Subject = userID

	// Load Cognito claims from cache if available, scoped to the request's tenant
	// so one tenant cannot read another's cached claims for a colliding sub.
	tenantSlug := tenantSlugFromIssuer(op.IssuerFromContext(ctx))
	var uc *userClaims
	if cached, ok := s.userClaims.Load(claimsKey(tenantSlug, userID)); ok {
		uc = cached.(*userClaims)
	}

	// Populate claims based on requested scopes.
	for _, scope := range scopes {
		switch scope {
		case "email":
			if uc != nil && uc.Email != "" {
				userinfo.Email = uc.Email
			} else {
				userinfo.Email = userID // Fallback to userID
			}
			// email_verified reflects Cognito's real claim, never a hard-coded
			// true. With no cached claims (uc == nil) it stays false: an
			// unverified or unknown address must not be advertised as verified.
			userinfo.EmailVerified = oidc.Bool(uc != nil && uc.EmailVerified)
		case "profile":
			if uc != nil {
				if uc.GivenName != "" && uc.FamilyName != "" {
					userinfo.Name = uc.GivenName + " " + uc.FamilyName
				}
				if uc.GivenName != "" {
					userinfo.GivenName = uc.GivenName
				}
				if uc.FamilyName != "" {
					userinfo.FamilyName = uc.FamilyName
				}
				if uc.Email != "" {
					userinfo.PreferredUsername = uc.Email
				} else {
					userinfo.PreferredUsername = userID
				}
			} else {
				userinfo.PreferredUsername = userID
			}
		}
	}
	return nil
}

// SetUserinfoFromToken populates userinfo from a stored token.
func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	// RFC 7662 §2.2 / RFC 6750: userinfo MUST NOT be served for an expired or
	// revoked access token. Revocation deletes the record, so a missing record is
	// treated as dead; an existing record must not be past its expiry.
	var item accessTokenItem
	if err := s.db.Get(ctx, oidcAccessTokenPK(tokenID), oidcAccessTokenSK(), &item); err != nil {
		return fmt.Errorf("access token not found or revoked: %w", err)
	}
	if !item.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("access token expired")
	}

	userinfo.Subject = subject

	// Enrich with cached user claims, scoped to the request's tenant so a colliding
	// sub across tenants cannot leak another tenant's claims.
	tenantSlug := tenantSlugFromIssuer(op.IssuerFromContext(ctx))
	if cached, ok := s.userClaims.Load(claimsKey(tenantSlug, subject)); ok {
		uc := cached.(*userClaims)
		if uc.Email != "" {
			userinfo.Email = uc.Email
		} else {
			userinfo.Email = subject // Fallback to subject
		}
		// Real Cognito email_verified claim, not a hard-coded true.
		userinfo.EmailVerified = oidc.Bool(uc.EmailVerified)

		if uc.GivenName != "" && uc.FamilyName != "" {
			userinfo.Name = uc.GivenName + " " + uc.FamilyName
		}
		if uc.GivenName != "" {
			userinfo.GivenName = uc.GivenName
		}
		if uc.FamilyName != "" {
			userinfo.FamilyName = uc.FamilyName
		}
		if uc.Email != "" {
			userinfo.PreferredUsername = uc.Email
		} else {
			userinfo.PreferredUsername = subject
		}
	} else {
		// No cached claims: fall back to the subject as the address, but it is
		// synthetic and unverified, so email_verified is false. Emitting
		// true here would let a relying party trust an address the gateway never
		// confirmed.
		userinfo.Email = subject
		userinfo.EmailVerified = oidc.Bool(false)
		userinfo.PreferredUsername = subject
	}

	return nil
}

// SetIntrospectionFromToken populates introspection response from a stored token.
func (s *Storage) SetIntrospectionFromToken(ctx context.Context, resp *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	// Look up the token. A missing record means the token is unknown or was
	// revoked (revocation deletes the record), so it is inactive.
	var item accessTokenItem
	if err := s.db.Get(ctx, oidcAccessTokenPK(tokenID), oidcAccessTokenSK(), &item); err != nil {
		resp.Active = false
		return fmt.Errorf("token not found: %w", err)
	}

	// RFC 7662 §2.2: an expired token MUST introspect as inactive. The
	// zitadel/oidc handler forces Active=true whenever this method returns nil,
	// so a dead token must return an error to keep the response at active=false
	// and avoid leaking Subject/Scope/ClientID for a token that is no longer
	// valid.
	if !item.ExpiresAt.After(time.Now()) {
		resp.Active = false
		return fmt.Errorf("token expired")
	}

	resp.Active = true
	resp.Subject = item.Subject
	resp.Scope = item.Scopes
	resp.ClientID = item.ClientID
	resp.TokenType = oidc.BearerToken
	resp.Expiration = oidc.FromTime(item.ExpiresAt)

	// Enrich with cached user claims, scoped to the request's tenant so a colliding
	// sub across tenants cannot leak another tenant's claims.
	tenantSlug := tenantSlugFromIssuer(op.IssuerFromContext(ctx))
	if cached, ok := s.userClaims.Load(claimsKey(tenantSlug, item.Subject)); ok {
		uc := cached.(*userClaims)
		resp.Username = uc.Email
		resp.Email = uc.Email
		// Real Cognito email_verified claim, not a hard-coded true.
		resp.EmailVerified = oidc.Bool(uc.EmailVerified)
		if uc.GivenName != "" && uc.FamilyName != "" {
			resp.Name = uc.GivenName + " " + uc.FamilyName
		}
		resp.GivenName = uc.GivenName
		resp.FamilyName = uc.FamilyName
	}

	return nil
}

// GetPrivateClaimsFromScopes returns additional private claims based on scopes.
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	// zitadel/oidc calls this with standard scopes (email, profile) REMOVED.
	// Standard claims are set via SetUserinfoFromScopes which zitadel merges into the token.
	// Here we only add non-standard private claims like groups.
	claims := make(map[string]any)

	// Tenant-scoped cache lookup so a colliding sub cannot pull another tenant's
	// groups into this token.
	tenantSlug := tenantSlugFromIssuer(op.IssuerFromContext(ctx))
	cached, ok := s.userClaims.Load(claimsKey(tenantSlug, userID))
	if !ok {
		return nil, nil
	}
	uc := cached.(*userClaims)

	if len(uc.Groups) > 0 {
		claims["groups"] = uc.Groups
	}

	if len(claims) == 0 {
		return nil, nil
	}
	return claims, nil
}

// GetKeyByIDAndClientID returns a JWK by key ID and client ID (for JWT profile grant).
func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, fmt.Errorf("JWT profile grant not supported")
}

// ValidateJWTProfileScopes validates scopes for JWT profile grants.
func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

// Health returns nil if the storage is healthy.
func (s *Storage) Health(ctx context.Context) error {
	return nil
}
