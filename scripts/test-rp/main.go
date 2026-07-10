// Test OIDC Relying Party for local development.
//
// Usage:
//
//	go run scripts/test-rp/main.go
//
// Environment variables:
//
//	RP_PORT             — HTTP port (default: 8082)
//	RP_CLIENT_ID        — OIDC client ID (default: auto-detected from gateway)
//	GATEWAY_URL         — Federation Gateway base URL (default: http://localhost:8080)
//	TENANT_SLUG         — Tenant slug (default: local)
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	httpadapter "github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
)

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	port        string
	clientID    string
	gatewayURL  string
	tenantSlug  string
	issuer      string
	authzURL    string
	tokenURL    string
	callbackURL string

	// PKCE verifier stored per-session (simplistic — single user)
	pkceVerifier string
	stateParam   string
)

var initOnce sync.Once
var initErr error

func ensureInit() error {
	initOnce.Do(func() {
		issuer = fmt.Sprintf("%s/t/%s/oidc", gatewayURL, tenantSlug)
		discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", issuer)

		log.Printf("Fetching OIDC discovery from %s", discoveryURL)
		disc, err := fetchDiscovery(discoveryURL)
		if err != nil {
			initErr = fmt.Errorf("failed to fetch OIDC discovery: %w", err)
			return
		}
		authzURL = disc["authorization_endpoint"].(string)
		tokenURL = disc["token_endpoint"].(string)
		log.Printf("Authorization endpoint: %s", authzURL)
		log.Printf("Token endpoint: %s", tokenURL)

		if clientID == "" {
			clientID = detectClientID()
		}
		log.Printf("Client ID: %s", clientID)
	})
	return initErr
}

func main() {
	port = getEnv("RP_PORT", "8082")
	clientID = getEnv("RP_CLIENT_ID", "")
	gatewayURL = getEnv("GATEWAY_URL", "http://localhost:8080")
	tenantSlug = getEnv("TENANT_SLUG", "local")
	if rpDomain := os.Getenv("RP_DOMAIN"); rpDomain != "" {
		callbackURL = fmt.Sprintf("https://%s/callback", rpDomain)
	} else {
		callbackURL = fmt.Sprintf("http://localhost:%s/callback", port)
	}

	// In non-Lambda mode, discover eagerly
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") == "" {
		if err := ensureInit(); err != nil {
			log.Fatalf("%v", err)
		}
	}

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	// Lambda or HTTP server mode
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		log.Println("Starting in Lambda mode")
		adapter := httpadapter.NewV2(http.DefaultServeMux)
		lambda.Start(adapter.ProxyWithContext)
	} else {
		log.Printf("Test OIDC RP listening on http://localhost:%s", port)
		log.Printf("  Login: http://localhost:%s/login", port)
		log.Fatal(http.ListenAndServe(":"+port, nil))
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if err := ensureInit(); err != nil {
		http.Error(w, fmt.Sprintf("Init error: %v", err), http.StatusInternalServerError)
		return
	}
	tmpl := template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html>
<head><title>Test OIDC RP</title>
<style>
body { font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
h1 { color: #232f3e; }
.card { background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 20px 0; }
.btn { background: #0972d3; color: white; padding: 10px 24px; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; text-decoration: none; display: inline-block; }
.btn:hover { background: #065299; }
code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-size: 14px; }
pre { background: #1a1a2e; color: #e0e0e0; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
</style>
</head>
<body>
<h1>Test OIDC Relying Party</h1>
<div class="card">
  <p><strong>Gateway:</strong> <code>{{.GatewayURL}}</code></p>
  <p><strong>Tenant:</strong> <code>{{.TenantSlug}}</code></p>
  <p><strong>Client ID:</strong> <code>{{.ClientID}}</code></p>
  <p><strong>Callback URL:</strong> <code>{{.CallbackURL}}</code></p>
</div>
<a href="/login" class="btn">Login with OIDC</a>
</body>
</html>`))
	tmpl.Execute(w, map[string]string{
		"GatewayURL":  gatewayURL,
		"TenantSlug":  tenantSlug,
		"ClientID":    clientID,
		"CallbackURL": callbackURL,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := ensureInit(); err != nil {
		http.Error(w, fmt.Sprintf("Init error: %v", err), http.StatusInternalServerError)
		return
	}
	// Generate PKCE
	verifierBytes := make([]byte, 32)
	rand.Read(verifierBytes)
	pkceVerifier = base64.RawURLEncoding.EncodeToString(verifierBytes)
	challenge := sha256.Sum256([]byte(pkceVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challenge[:])

	// Generate state
	stateBytes := make([]byte, 16)
	rand.Read(stateBytes)
	stateParam = base64.RawURLEncoding.EncodeToString(stateBytes)

	params := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {callbackURL},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {stateParam},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	redirectURL := fmt.Sprintf("%s?%s", authzURL, params.Encode())
	log.Printf("Redirecting to: %s", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		// errParam/errDesc are attacker-controlled query parameters; HTML-escape
		// them before reflecting into the page to prevent reflected XSS.
		fmt.Fprintf(w, `<html><body><h1>Error</h1><p>%s: %s</p><a href="/">Back</a></body></html>`,
			template.HTMLEscapeString(errParam), template.HTMLEscapeString(errDesc))
		return
	}

	if state != stateParam {
		http.Error(w, "State mismatch — possible CSRF", http.StatusForbidden)
		return
	}

	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	log.Printf("Exchanging code for tokens at %s", tokenURL)
	tokens, err := exchangeCode(code)
	if err != nil {
		// The error can echo server responses derived from request input; escape
		// before reflecting into HTML.
		fmt.Fprintf(w, `<html><body><h1>Token Exchange Failed</h1><pre>%s</pre><a href="/">Back</a></body></html>`,
			template.HTMLEscapeString(err.Error()))
		return
	}

	// Decode ID token (without verification — for display only)
	idToken, _ := tokens["id_token"].(string)
	var claims map[string]interface{}
	if idToken != "" {
		parts := strings.Split(idToken, ".")
		if len(parts) == 3 {
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			json.Unmarshal(payload, &claims)
		}
	}

	// Render result
	tmpl := template.Must(template.New("result").Parse(`<!DOCTYPE html>
<html>
<head><title>OIDC Login Result</title>
<style>
body { font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
h1 { color: #1a8038; }
h2 { color: #232f3e; margin-top: 30px; }
.card { background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 20px 0; }
pre { background: #1a1a2e; color: #e0e0e0; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
.btn { background: #0972d3; color: white; padding: 10px 24px; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; text-decoration: none; display: inline-block; }
code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; }
</style>
</head>
<body>
<h1>Authentication Successful</h1>
<div class="card">
  <p><strong>Subject:</strong> <code>{{.Sub}}</code></p>
  <p><strong>Email:</strong> <code>{{.Email}}</code></p>
  <p><strong>Name:</strong> <code>{{.Name}}</code></p>
</div>
<h2>ID Token Claims</h2>
<pre>{{.ClaimsJSON}}</pre>
<h2>Token Response</h2>
<pre>{{.TokensJSON}}</pre>
<a href="/" class="btn">Back to Home</a>
</body>
</html>`))

	claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
	tokensJSON, _ := json.MarshalIndent(tokens, "", "  ")

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	tmpl.Execute(w, map[string]string{
		"Sub":        sub,
		"Email":      email,
		"Name":       name,
		"ClaimsJSON": string(claimsJSON),
		"TokensJSON": string(tokensJSON),
	})

	log.Printf("Login successful: sub=%s email=%s", sub, email)
}

func exchangeCode(code string) (map[string]interface{}, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL},
		"client_id":     {clientID},
		"code_verifier": {pkceVerifier},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return result, nil
}

func fetchDiscovery(url string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func detectClientID() string {
	// Fetch apps from the gateway and find the OIDC one
	appsURL := fmt.Sprintf("%s/api/v1/applications", gatewayURL)
	resp, err := http.Get(appsURL)
	if err != nil {
		log.Printf("Could not auto-detect client ID: %v", err)
		return "unknown"
	}
	defer resp.Body.Close()

	var apps []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&apps)

	for _, app := range apps {
		if p, ok := app["protocol"].(string); ok && p == "oidc" {
			if id, ok := app["id"].(string); ok {
				log.Printf("Auto-detected OIDC client ID: %s", id)
				return id
			}
		}
	}

	log.Printf("No OIDC app found — create one via the management API")
	return "unknown"
}
