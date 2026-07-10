package tui

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// ErrNoToken indicates that no bearer token was configured for the API client.
// The client fails closed on this condition: it never issues an unauthenticated
// request and callers must NOT degrade to mock data. It is surfaced verbatim in
// the TUI so the operator sees a clear, actionable authentication error.
var ErrNoToken = errors.New("not authenticated: set FEDCTL_TOKEN to a Cognito-issued JWT (or FEDCTL_OFFLINE=1 for offline mock mode)")

// errOffline is returned when the client is in explicit offline mode (operator
// set FEDCTL_OFFLINE). Unlike ErrNoToken, this is a sanctioned, opt-in state:
// no request is made and the TUI intentionally shows mock data.
var errOffline = errors.New("offline mode: management API not contacted")

// APIClient wraps the gateway REST API
type APIClient struct {
	baseURL string
	// token is a Cognito-issued JWT attached as "Authorization: Bearer <token>"
	// on every request. The management gateway (middleware.RequireAuth) rejects
	// any mutation lacking it, so it must be present for real operation.
	token   string
	offline bool
	http    *http.Client
}

// NewAPIClient creates a new API client. token is a Cognito-issued JWT; when
// empty and offline is false the client fails closed (see newRequest). When
// offline is true the client makes no requests and callers fall back to mock
// data — an explicit, operator-selected mode, never a silent default.
func NewAPIClient(baseURL, token string, offline bool) *APIClient {
	return &APIClient{
		baseURL: baseURL,
		token:   token,
		offline: offline,
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// newRequest builds an authenticated request, attaching the bearer token to
// every call. It fails closed when no token is configured: rather than issuing
// an unauthenticated request (or letting the caller silently degrade to mock
// data), it returns ErrNoToken. In explicit offline mode it returns errOffline
// without building a request.
func (c *APIClient) newRequest(method, url string, body io.Reader) (*http.Request, error) {
	if c.token == "" {
		if c.offline {
			return nil, errOffline
		}
		return nil, ErrNoToken
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return req, nil
}

// Message types for async operations

type TenantsLoadedMsg struct {
	Tenants []TenantInfo
	Err     error
}

type ApplicationsLoadedMsg struct {
	Applications []ApplicationInfo
	Err          error
}

type HealthLoadedMsg struct {
	Health HealthInfo
	Err    error
}

type AssertionDecodedMsg struct {
	Decoded string
	Err     error
}

// Data structures

type TenantInfo struct {
	Slug        string    `json:"slug"`
	DisplayName string    `json:"display_name"`
	Plan        string    `json:"plan"`
	Status      string    `json:"status"`
	AppCount    int       `json:"app_count"`
	CreatedAt   time.Time `json:"created_at"`
}

type ApplicationInfo struct {
	Name           string    `json:"name"`
	Protocol       string    `json:"protocol"`
	IdentitySource string    `json:"identity_source"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	TenantSlug     string    `json:"tenant_slug"`
}

type HealthInfo struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	SAMLOk    bool   `json:"saml_ok"`
	OIDCOk    bool   `json:"oidc_ok"`
}

// API methods returning tea.Cmd

func (c *APIClient) ListTenants() tea.Cmd {
	return func() tea.Msg {
		req, err := c.newRequest(http.MethodGet, c.baseURL+"/api/v1/tenants", nil)
		if err != nil {
			return TenantsLoadedMsg{Err: err}
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return TenantsLoadedMsg{Err: err}
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return TenantsLoadedMsg{Err: fmt.Errorf("API error: %s", body)}
		}

		var result struct {
			Tenants []TenantInfo `json:"tenants"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return TenantsLoadedMsg{Err: err}
		}

		return TenantsLoadedMsg{Tenants: result.Tenants}
	}
}

// TenantMutatedMsg reports the result of a create/delete tenant operation.
type TenantMutatedMsg struct {
	Action string // "created" or "deleted"
	Slug   string
	Err    error
}

// CreateTenant creates a new tenant via the management API.
func (c *APIClient) CreateTenant(slug, displayName string) tea.Cmd {
	return func() tea.Msg {
		payload, _ := json.Marshal(map[string]string{"slug": slug, "displayName": displayName})
		req, err := c.newRequest(http.MethodPost, c.baseURL+"/api/v1/tenants", bytes.NewReader(payload))
		if err != nil {
			return TenantMutatedMsg{Action: "created", Slug: slug, Err: err}
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return TenantMutatedMsg{Action: "created", Slug: slug, Err: err}
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)
			return TenantMutatedMsg{Action: "created", Slug: slug, Err: fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))}
		}
		return TenantMutatedMsg{Action: "created", Slug: slug}
	}
}

// DeleteTenant deletes a tenant via the management API.
func (c *APIClient) DeleteTenant(slug string) tea.Cmd {
	return func() tea.Msg {
		req, err := c.newRequest(http.MethodDelete, c.baseURL+"/api/v1/tenants/"+slug, nil)
		if err != nil {
			return TenantMutatedMsg{Action: "deleted", Slug: slug, Err: err}
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return TenantMutatedMsg{Action: "deleted", Slug: slug, Err: err}
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)
			return TenantMutatedMsg{Action: "deleted", Slug: slug, Err: fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))}
		}
		return TenantMutatedMsg{Action: "deleted", Slug: slug}
	}
}

func (c *APIClient) ListApplications(tenant string) tea.Cmd {
	return func() tea.Msg {
		url := fmt.Sprintf("%s/api/v1/tenants/%s/applications", c.baseURL, tenant)
		req, err := c.newRequest(http.MethodGet, url, nil)
		if err != nil {
			return ApplicationsLoadedMsg{Err: err}
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return ApplicationsLoadedMsg{Err: err}
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return ApplicationsLoadedMsg{Err: fmt.Errorf("API error: %s", body)}
		}

		var result struct {
			Applications []ApplicationInfo `json:"applications"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return ApplicationsLoadedMsg{Err: err}
		}

		return ApplicationsLoadedMsg{Applications: result.Applications}
	}
}

func (c *APIClient) GetHealth() tea.Cmd {
	return func() tea.Msg {
		req, err := c.newRequest(http.MethodGet, c.baseURL+"/health", nil)
		if err != nil {
			return HealthLoadedMsg{Err: err}
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return HealthLoadedMsg{Err: err}
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			return HealthLoadedMsg{Err: fmt.Errorf("health check failed: status %d", resp.StatusCode)}
		}

		var health HealthInfo
		if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
			return HealthLoadedMsg{Err: err}
		}

		return HealthLoadedMsg{Health: health}
	}
}

func (c *APIClient) DecodeAssertion(base64String string) tea.Cmd {
	return func() tea.Msg {
		// Decode base64
		decoded, err := base64.StdEncoding.DecodeString(base64String)
		if err != nil {
			return AssertionDecodedMsg{Err: fmt.Errorf("invalid base64: %w", err)}
		}

		// Try to parse as XML (SAML)
		var xmlDoc interface{}
		if err := xml.Unmarshal(decoded, &xmlDoc); err == nil {
			// Pretty print XML
			formatted, err := formatXML(decoded)
			if err != nil {
				return AssertionDecodedMsg{Decoded: string(decoded)}
			}
			return AssertionDecodedMsg{Decoded: formatted}
		}

		// Try to parse as JWT (OIDC token) - simplified check
		// Just return the decoded string for now
		return AssertionDecodedMsg{Decoded: string(decoded)}
	}
}

// formatXML attempts to pretty-print XML
func formatXML(data []byte) (string, error) {
	var v interface{}
	if err := xml.Unmarshal(data, &v); err != nil {
		return "", err
	}

	formatted, err := xml.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}

	return string(formatted), nil
}
