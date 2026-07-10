package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"html"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	httpadapter "github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// NewHTTPAdapter wraps stdlib http.Handler for Lambda API Gateway v2 events.
func NewHTTPAdapter(h http.Handler) *httpadapter.HandlerAdapterV2 {
	return httpadapter.NewV2(h)
}

var sp *saml.ServiceProvider

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	entityID := getEnv("SP_ENTITY_ID", "https://test-sp.local")
	acsURL := getEnv("SP_ACS_URL", "http://localhost:8081/saml/acs")
	port := getEnv("SP_PORT", "8081")
	idpMetadataURL := getEnv("IDP_METADATA_URL", "http://localhost:8080/t/local/saml/metadata")

	log.Printf("Starting SAML Test SP on :%s (Entity: %s, ACS: %s)", port, entityID, acsURL)

	keyPair, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate cert: %v", err)
	}
	keyPair.Leaf, _ = x509.ParseCertificate(keyPair.Certificate[0])

	log.Printf("Fetching IdP metadata from %s", idpMetadataURL)
	metaURL, _ := url.Parse(idpMetadataURL)
	idpMeta, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *metaURL)
	if err != nil {
		log.Fatalf("Failed to fetch IdP metadata: %v", err)
	}
	log.Printf("IdP metadata loaded (Entity: %s)", idpMeta.EntityID)

	acs, _ := url.Parse(acsURL)
	metaURLParsed, _ := url.Parse(acsURL)
	metaURLParsed.Path = "/saml/metadata"

	sp = &saml.ServiceProvider{
		EntityID:          entityID,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		MetadataURL:       *metaURLParsed,
		AcsURL:            *acs,
		IDPMetadata:       idpMeta,
		AllowIDPInitiated: true,
	}

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/saml/metadata", handleMetadata)
	http.HandleFunc("/saml/login", handleLogin)
	http.HandleFunc("/saml/acs", handleACS)

	// Lambda or HTTP server mode
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		log.Println("Starting in Lambda mode")
		adapter := NewHTTPAdapter(http.DefaultServeMux)
		lambda.Start(adapter.ProxyWithContext)
	} else {
		log.Printf("Listening on http://localhost:%s", port)
		log.Fatal(http.ListenAndServe(":"+port, nil))
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>SAML Test SP</title><style>body{font-family:sans-serif;max-width:800px;margin:50px auto;padding:20px}.box{border:1px solid #ccc;padding:20px;border-radius:5px;background:#f9f9f9}a.button{display:inline-block;padding:10px 20px;background:#007bff;color:white;text-decoration:none;border-radius:4px;margin-top:10px}a.button:hover{background:#0056b3}</style></head><body><h1>SAML Test Service Provider</h1><div class="box"><h2>Welcome!</h2><p>Minimal SAML SP for testing.</p><a href="/saml/login" class="button">Login via SAML</a><p style="margin-top:20px"><a href="/saml/metadata">View SP Metadata</a></p></div></body></html>`)
}

func handleMetadata(w http.ResponseWriter, r *http.Request) {
	meta, _ := xml.MarshalIndent(sp.Metadata(), "", "  ")
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(meta)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	log.Println("Creating SAML AuthnRequest...")
	authnReq, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPPostBinding, saml.HTTPPostBinding)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("AuthnRequest ID: %s", authnReq.ID)
	redirectURL, _ := authnReq.Redirect("", sp)
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func handleACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	samlResp := r.FormValue("SAMLResponse")
	relayState := r.FormValue("RelayState")

	log.Println("======================================== SAML ACS ========================================")
	log.Printf("SAMLResponse: %d bytes, RelayState: %s", len(samlResp), relayState)

	samlXML, err := base64.StdEncoding.DecodeString(samlResp)
	if err != nil {
		log.Printf("ERROR decoding: %v", err)
		http.Error(w, "Invalid SAMLResponse", http.StatusBadRequest)
		return
	}

	log.Println("--- Decoded SAML Response XML ---")
	log.Println(string(samlXML))
	log.Println("--- End ---")

	assertion, err := sp.ParseResponse(r, []string{})
	if err != nil {
		log.Printf("ERROR: %v", err)
		showError(w, err, string(samlXML))
		return
	}

	nameID := assertion.Subject.NameID.Value
	log.Printf("=== SUCCESS: NameID=%s ===", nameID)

	var attrs []string
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			for _, val := range attr.Values {
				log.Printf("  %s: %s", attr.Name, val.Value)
				attrs = append(attrs, fmt.Sprintf("<tr><td>%s</td><td>%s</td></tr>", html.EscapeString(attr.Name), html.EscapeString(val.Value)))
			}
		}
	}

	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>SAML Success</title><style>body{font-family:sans-serif;max-width:800px;margin:50px auto;padding:20px}.box{border:1px solid #ccc;padding:20px;border-radius:5px;background:#e8f5e9}table{width:100%%;border-collapse:collapse;margin-top:20px}th,td{text-align:left;padding:8px;border-bottom:1px solid #ddd}th{background:#4caf50;color:white}.success{color:#2e7d32}</style></head><body><h1 class="success">✓ SAML Authentication Successful</h1><div class="box"><h2>User Information</h2><p><strong>NameID:</strong> %s</p><h3>SAML Attributes</h3><table><tr><th>Attribute</th><th>Value</th></tr>%s</table><p style="margin-top:20px"><a href="/">Back to Home</a></p></div></body></html>`, html.EscapeString(nameID), strings.Join(attrs, ""))
}

func showError(w http.ResponseWriter, err error, rawXML string) {
	log.Printf("Showing error page: %v", err)
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>SAML Error</title><style>body{font-family:sans-serif;max-width:900px;margin:50px auto;padding:20px}.box{border:1px solid #ccc;padding:20px;border-radius:5px;background:#ffebee}pre{background:#f5f5f5;padding:10px;overflow-x:auto;border:1px solid #ddd}.error{color:#c62828}</style></head><body><h1 class="error">✗ SAML Authentication Failed</h1><div class="box"><h2>Error</h2><p>%s</p><h3>Raw SAML Response (for debugging)</h3><pre>%s</pre><p style="margin-top:20px"><a href="/">Back to Home</a></p></div></body></html>`, html.EscapeString(err.Error()), html.EscapeString(rawXML))
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Test SP"}, CommonName: "test-sp.local"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
