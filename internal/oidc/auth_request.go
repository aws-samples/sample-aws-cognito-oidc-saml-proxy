package oidc

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// AuthRequest implements op.AuthRequest for the authorization code flow.
// It is stored in DynamoDB during the auth flow and retrieved by ID or auth code.
type AuthRequest struct {
	ID            string              `dynamo:"id" json:"id"`
	ClientID      string              `dynamo:"clientID" json:"clientID"`
	RedirectURI   string              `dynamo:"redirectURI" json:"redirectURI"`
	Scopes        []string            `dynamo:"scopes" json:"scopes"`
	State         string              `dynamo:"state" json:"state"`
	Nonce         string              `dynamo:"nonce" json:"nonce"`
	ResponseType  oidc.ResponseType   `dynamo:"responseType" json:"responseType"`
	ResponseMode  oidc.ResponseMode   `dynamo:"responseMode" json:"responseMode"`
	CodeChallenge *oidc.CodeChallenge `dynamo:"-" json:"-"`
	CreatedAt     time.Time           `dynamo:"createdAt" json:"createdAt"`
	AuthTime      time.Time           `dynamo:"authTime" json:"authTime"`
	UserID        string              `dynamo:"userID" json:"userID"`
	IsDone        bool                `dynamo:"isDone" json:"isDone"`
	TenantSlug    string              `dynamo:"tenantSlug" json:"tenantSlug"`
	SourceID      string              `dynamo:"sourceID" json:"sourceID"`
	AuthCode      string              `dynamo:"authCode" json:"authCode"`

	// PKCE fields stored separately since CodeChallenge is a pointer struct
	CodeChallengeValue  string `dynamo:"codeChallengeValue" json:"codeChallengeValue"`
	CodeChallengeMethod string `dynamo:"codeChallengeMethod" json:"codeChallengeMethod"`

	// Cognito claims extracted during the callback (email, name, groups, custom attrs)
	CognitoEmail         string   `dynamo:"cognitoEmail" json:"cognitoEmail,omitempty"`
	CognitoGivenName     string   `dynamo:"cognitoGivenName" json:"cognitoGivenName,omitempty"`
	CognitoFamilyName    string   `dynamo:"cognitoFamilyName" json:"cognitoFamilyName,omitempty"`
	CognitoEmailVerified bool     `dynamo:"cognitoEmailVerified" json:"cognitoEmailVerified,omitempty"`
	CognitoGroups        []string `dynamo:"cognitoGroups" json:"cognitoGroups,omitempty"`
}

func (a *AuthRequest) GetID() string                         { return a.ID }
func (a *AuthRequest) GetACR() string                        { return "0" }
func (a *AuthRequest) GetAMR() []string                      { return []string{"pwd"} }
func (a *AuthRequest) GetAudience() []string                 { return []string{a.ClientID} }
func (a *AuthRequest) GetAuthTime() time.Time                { return a.AuthTime }
func (a *AuthRequest) GetClientID() string                   { return a.ClientID }
func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge { return a.CodeChallenge }
func (a *AuthRequest) GetNonce() string                      { return a.Nonce }
func (a *AuthRequest) GetRedirectURI() string                { return a.RedirectURI }
func (a *AuthRequest) GetResponseType() oidc.ResponseType    { return a.ResponseType }
func (a *AuthRequest) GetResponseMode() oidc.ResponseMode    { return a.ResponseMode }
func (a *AuthRequest) GetScopes() []string                   { return a.Scopes }
func (a *AuthRequest) GetState() string                      { return a.State }
func (a *AuthRequest) GetSubject() string                    { return a.UserID }
func (a *AuthRequest) Done() bool                            { return a.IsDone }
