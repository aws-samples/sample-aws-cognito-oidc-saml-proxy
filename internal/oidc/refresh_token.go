package oidc

import (
	"fmt"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// defaultRefreshTokenLifetime is used when the client's OIDCConfig does not
// specify RefreshTokenLifetimeSec. 30 days is a common default for
// interactive web/native apps that use offline_access.
const defaultRefreshTokenLifetime = 30 * 24 * time.Hour

// DynamoDB key helpers for refresh-token items. Each token gets its own
// partition key (opaque high-entropy value) to avoid hot partitions.
func oidcRefreshTokenPK(token string) string { return fmt.Sprintf("REFRESHTOKEN#%s", token) }
func oidcRefreshTokenSK() string             { return "META" }

// refreshTokenItem is the DynamoDB record backing an issued refresh token.
// It stores everything needed to reconstruct the original authorization
// context (a RefreshTokenRequest) plus the Cognito claims required to keep the
// re-issued ID token / userinfo response populated across refreshes — the
// refresh grant runs on the oidc-token Lambda, which never saw the login.
type refreshTokenItem struct {
	PK        string    `dynamo:"PK,hash" json:"-"`
	SK        string    `dynamo:"SK,range" json:"-"`
	TTL       int64     `dynamo:"ttl" json:"-"` // DynamoDB TTL — auto-delete after expiry
	Token     string    `dynamo:"token" json:"token"`
	Subject   string    `dynamo:"subject" json:"subject"`
	ClientID  string    `dynamo:"clientID" json:"clientID"`
	Audience  []string  `dynamo:"audience" json:"audience"`
	Scopes    []string  `dynamo:"scopes" json:"scopes"`
	AMR       []string  `dynamo:"amr" json:"amr"`
	AuthTime  time.Time `dynamo:"authTime" json:"authTime"`
	ExpiresAt time.Time `dynamo:"expiresAt" json:"expiresAt"`

	// Cognito claims carried alongside the token so they survive refresh.
	Email            string            `dynamo:"email" json:"email,omitempty"`
	GivenName        string            `dynamo:"givenName" json:"givenName,omitempty"`
	FamilyName       string            `dynamo:"familyName" json:"familyName,omitempty"`
	EmailVerified    bool              `dynamo:"emailVerified" json:"emailVerified,omitempty"`
	Groups           []string          `dynamo:"groups" json:"groups,omitempty"`
	CustomAttributes map[string]string `dynamo:"customAttributes,omitempty" json:"customAttributes,omitempty"`
}

// claims rebuilds the SubjectClaims persisted on the refresh-token record.
func (i *refreshTokenItem) claims() SubjectClaims {
	return SubjectClaims{
		Sub:              i.Subject,
		Email:            i.Email,
		EmailVerified:    i.EmailVerified,
		GivenName:        i.GivenName,
		FamilyName:       i.FamilyName,
		Groups:           i.Groups,
		CustomAttributes: i.CustomAttributes,
	}
}

// refreshTokenRequest implements op.RefreshTokenRequest (and, by extension, the
// subset of op.TokenRequest that token creation needs). It represents the
// original authorization context recovered from a stored refresh token.
type refreshTokenRequest struct {
	clientID string
	subject  string
	audience []string
	scopes   []string
	amr      []string
	authTime time.Time

	// claims are carried forward so a rotated refresh token keeps the same
	// Cognito claims without another Cognito round-trip.
	claims SubjectClaims
}

func (r *refreshTokenRequest) GetAMR() []string            { return r.amr }
func (r *refreshTokenRequest) GetAudience() []string       { return r.audience }
func (r *refreshTokenRequest) GetAuthTime() time.Time      { return r.authTime }
func (r *refreshTokenRequest) GetClientID() string         { return r.clientID }
func (r *refreshTokenRequest) GetScopes() []string         { return r.scopes }
func (r *refreshTokenRequest) GetSubject() string          { return r.subject }
func (r *refreshTokenRequest) SetCurrentScopes(s []string) { r.scopes = s }

// refreshableRequest is the common surface of *AuthRequest and
// *refreshTokenRequest used when persisting a refresh token. Both the initial
// authorization-code exchange (*AuthRequest) and refresh-token rotation
// (*refreshTokenRequest) satisfy it.
type refreshableRequest interface {
	GetSubject() string
	GetAudience() []string
	GetScopes() []string
	GetClientID() string
	GetAMR() []string
	GetAuthTime() time.Time
}

// claimsFromRequest extracts the persisted Cognito claims from a token request:
// the *AuthRequest loaded by code on the initial exchange or the
// *refreshTokenRequest rebuilt from the refresh-token record on rotation. Any
// other request type carries no claims and yields the zero value (subject
// only) — never a synthesised email.
func claimsFromRequest(req op.TokenRequest) SubjectClaims {
	switch r := req.(type) {
	case *AuthRequest:
		return SubjectClaims{
			Sub:              r.UserID,
			Email:            r.CognitoEmail,
			EmailVerified:    r.CognitoEmailVerified,
			GivenName:        r.CognitoGivenName,
			FamilyName:       r.CognitoFamilyName,
			Groups:           r.CognitoGroups,
			CustomAttributes: r.CognitoCustomAttributes,
		}
	case *refreshTokenRequest:
		return r.claims
	default:
		return SubjectClaims{Sub: req.GetSubject()}
	}
}
