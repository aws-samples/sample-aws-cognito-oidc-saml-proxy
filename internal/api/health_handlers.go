package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/service"
)

// HealthOutput defines the response schema for the health check
type HealthOutput struct {
	Body struct {
		Status      string    `json:"status" doc:"Health status" example:"ok"`
		Timestamp   time.Time `json:"timestamp" doc:"Current server time"`
		Environment string    `json:"environment,omitempty" doc:"Deployment environment"`
	}
}

// CertEntry represents a single certificate with lifecycle status.
type CertEntry struct {
	ID            string `json:"id" doc:"Short identifier derived from fingerprint"`
	Role          string `json:"role" doc:"Certificate role: active or backup" example:"active"`
	Status        string `json:"status" doc:"Lifecycle status: active, pending, grace, retired" example:"active"`
	Source        string `json:"source" doc:"How the cert was produced: self-signed or ca-issued" example:"self-signed"`
	KMSKeyID      string `json:"kmsKeyId,omitempty" doc:"KMS key the cert public key belongs to"`
	Subject       string `json:"subject" doc:"Certificate subject CN"`
	Issuer        string `json:"issuer" doc:"Certificate issuer CN"`
	NotBefore     string `json:"notBefore" doc:"Valid from (RFC3339)"`
	NotAfter      string `json:"notAfter" doc:"Valid until (RFC3339)"`
	Fingerprint   string `json:"fingerprint" doc:"SHA-256 fingerprint (colon-separated hex)"`
	DaysRemaining int    `json:"daysRemaining" doc:"Days until expiry"`
	IsExpired     bool   `json:"isExpired" doc:"Whether certificate has expired"`
	PemBase64     string `json:"pemBase64" doc:"Base64-encoded DER certificate for download"`
}

// CertListOutput defines the response schema for listing certificates.
type CertListOutput struct {
	Body struct {
		Certificates []CertEntry `json:"certificates" doc:"List of certificates with lifecycle status"`
	}
}

// CertRotateInput is the request body for certificate rotation (stub).
type CertRotateInput struct{}

// CertIDInput captures a certificate ID from the path.
type CertIDInput struct {
	ID string `path:"id" doc:"Certificate identifier"`
}

// CertCSRInput is the request body for generating a CSR.
type CertCSRInput struct {
	Body struct {
		Role string `json:"role" doc:"Certificate role: active or backup" enum:"active,backup" default:"active"`
	}
}

// CertCSROutput returns a PEM-encoded certificate signing request.
type CertCSROutput struct {
	Body struct {
		Role   string `json:"role" doc:"Certificate role the CSR was generated for"`
		CSRPem string `json:"csrPem" doc:"PEM-encoded PKCS#10 certificate signing request"`
	}
}

// CertImportInput is the request body for importing a CA-issued certificate.
type CertImportInput struct {
	Body struct {
		Role    string `json:"role" doc:"Certificate role: active or backup" enum:"active,backup" default:"active"`
		CertPem string `json:"certPem" doc:"PEM-encoded CA-issued leaf certificate (chain allowed; leaf must be first)"`
	}
}

// CertActionOutput is a generic acknowledgement for cert lifecycle actions.
type CertActionOutput struct {
	Body struct {
		Role        string `json:"role,omitempty" doc:"Affected certificate role"`
		Status      string `json:"status" doc:"Result status"`
		Message     string `json:"message" doc:"Human-readable result message"`
		Fingerprint string `json:"fingerprint,omitempty" doc:"Fingerprint of the imported certificate"`
		NotAfter    string `json:"notAfter,omitempty" doc:"Expiry of the imported certificate"`
	}
}

// CertErrorOutput defines the error response for certificate unavailability
type CertErrorOutput struct {
	Body struct {
		Message string `json:"message" doc:"Error message"`
	}
}

// certIDFromFingerprint derives a short ID from a colon-separated fingerprint.
func certIDFromFingerprint(fp string) string {
	// Remove colons and take first 8 hex chars
	clean := ""
	for _, c := range fp {
		if c != ':' {
			clean += string(c)
		}
	}
	if len(clean) > 8 {
		return clean[:8]
	}
	return clean
}

// RegisterHealthRoutes registers all health check routes
func RegisterHealthRoutes(api huma.API, certSvc *service.CertificateService, certMgr *service.CertManager) {
	// Basic health check
	huma.Register(api, huma.Operation{
		OperationID: "health-check",
		Method:      http.MethodGet,
		Path:        "/api/v1/health",
		Summary:     "Health check",
		Description: "Returns the current health status of the proxy service",
		Tags:        []string{"Health"},
	}, func(ctx context.Context, input *struct{}) (*HealthOutput, error) {
		return &HealthOutput{
			Body: struct {
				Status      string    `json:"status" doc:"Health status" example:"ok"`
				Timestamp   time.Time `json:"timestamp" doc:"Current server time"`
				Environment string    `json:"environment,omitempty" doc:"Deployment environment"`
			}{
				Status:    "ok",
				Timestamp: time.Now(),
			},
		}, nil
	})

	// Certificate list — returns all certificates with lifecycle status
	huma.Register(api, huma.Operation{
		OperationID: "list-certificates",
		Method:      http.MethodGet,
		Path:        "/api/v1/health/certificates",
		Summary:     "List certificates",
		Description: "Returns all IdP signing certificates with lifecycle status",
		Tags:        []string{"Certificates"},
	}, func(ctx context.Context, input *struct{}) (*CertListOutput, error) {
		out := &CertListOutput{}

		// Preferred path: list active + backup certs with provenance metadata.
		if certMgr != nil {
			managed, err := certMgr.List(ctx)
			if err != nil {
				return nil, huma.Error503ServiceUnavailable("certificate not available", err)
			}
			for _, mc := range managed {
				out.Body.Certificates = append(out.Body.Certificates, managedToEntry(mc))
			}
			if len(out.Body.Certificates) > 0 {
				return out, nil
			}
		}

		// Fallback: single active cert from the cold-start cert service.
		certInfo, err := certSvc.GetInfo()
		if err != nil {
			return nil, huma.Error503ServiceUnavailable("certificate not available", err)
		}
		out.Body.Certificates = []CertEntry{{
			ID:            certIDFromFingerprint(certInfo.Fingerprint),
			Role:          service.RoleActive,
			Status:        "active",
			Source:        "self-signed",
			Subject:       certInfo.Subject,
			Issuer:        certInfo.Issuer,
			NotBefore:     certInfo.NotBefore.Format(time.RFC3339),
			NotAfter:      certInfo.NotAfter.Format(time.RFC3339),
			Fingerprint:   certInfo.Fingerprint,
			DaysRemaining: certInfo.DaysRemaining,
			IsExpired:     certInfo.IsExpired,
			PemBase64:     certInfo.PemBase64,
		}}
		return out, nil
	})

	// Generate a CSR for an external CA to sign
	huma.Register(api, huma.Operation{
		OperationID: "generate-csr",
		Method:      http.MethodPost,
		Path:        "/api/v1/certificates/csr",
		Summary:     "Generate certificate signing request",
		Description: "Generates a PKCS#10 CSR for the active or backup KMS signing key. Submit it to an external CA; the private key never leaves KMS.",
		Tags:        []string{"Certificates"},
	}, func(ctx context.Context, input *CertCSRInput) (*CertCSROutput, error) {
		// Gateway-global signing operation: the CSR is generated against the
		// shared active/backup KMS signing key, not any tenant-scoped resource.
		// Authorize before the configuration check so a non-operator cannot
		// probe whether cert management is wired (fail closed on auth first).
		if err := requireGlobalOperator(ctx, "generate-csr", "forbidden: certificate signing is a gateway-global operation reserved for global operators"); err != nil {
			return nil, err
		}
		if certMgr == nil {
			return nil, huma.Error501NotImplemented("certificate management not configured")
		}
		role := normalizeRole(input.Body.Role)
		csrPEM, err := certMgr.GenerateCSR(role)
		if err != nil {
			return nil, huma.Error400BadRequest("failed to generate CSR", err)
		}
		out := &CertCSROutput{}
		out.Body.Role = role
		out.Body.CSRPem = string(csrPEM)
		return out, nil
	})

	// Import a CA-issued certificate for the active or backup role
	huma.Register(api, huma.Operation{
		OperationID: "import-certificate",
		Method:      http.MethodPost,
		Path:        "/api/v1/certificates/import",
		Summary:     "Import CA-issued certificate",
		Description: "Imports a CA-issued leaf certificate. The leaf public key must match the role's KMS key (pin-the-leaf).",
		Tags:        []string{"Certificates"},
	}, func(ctx context.Context, input *CertImportInput) (*CertActionOutput, error) {
		// MF-8: import pins a CA leaf onto the gateway-wide shared signing key
		// and affects every tenant. Require GlobalOperatorGroup, not per-tenant
		// Admins, and check before the configuration probe.
		if err := requireGlobalOperator(ctx, "import-certificate", "forbidden: certificate import is a gateway-global operation reserved for global operators"); err != nil {
			return nil, err
		}
		if certMgr == nil {
			return nil, huma.Error501NotImplemented("certificate management not configured")
		}
		role := normalizeRole(input.Body.Role)
		mc, err := certMgr.Import(ctx, role, []byte(input.Body.CertPem))
		if err != nil {
			return nil, huma.Error400BadRequest("failed to import certificate", err)
		}
		out := &CertActionOutput{}
		out.Body.Role = mc.Role
		out.Body.Status = "imported"
		out.Body.Message = "Certificate imported successfully"
		out.Body.Fingerprint = mc.Info.Fingerprint
		out.Body.NotAfter = mc.Info.NotAfter.Format(time.RFC3339)
		return out, nil
	})

	// Promote the backup certificate to active
	huma.Register(api, huma.Operation{
		OperationID: "promote-backup-certificate",
		Method:      http.MethodPost,
		Path:        "/api/v1/certificates/promote-backup",
		Summary:     "Promote backup certificate",
		Description: "Promotes the standby backup certificate to active. The backup is already published in SAML metadata, so relying parties trust it at promotion time.",
		Tags:        []string{"Certificates"},
	}, func(ctx context.Context, input *struct{}) (*CertActionOutput, error) {
		// MF-8: promote-backup rotates the active signing cert for the WHOLE IdP —
		// every tenant's SP trusts the new cert from this point forward. Only a
		// global operator may trigger it. Check before the configuration probe.
		if err := requireGlobalOperator(ctx, "promote-backup", "forbidden: certificate promotion is a gateway-global operation reserved for global operators"); err != nil {
			return nil, err
		}
		if certMgr == nil {
			return nil, huma.Error501NotImplemented("certificate management not configured")
		}
		if err := certMgr.PromoteBackup(ctx); err != nil {
			return nil, huma.Error400BadRequest("failed to promote backup certificate", err)
		}
		out := &CertActionOutput{}
		out.Body.Role = service.RoleActive
		out.Body.Status = "promoted"
		out.Body.Message = "Backup certificate promoted to active"
		return out, nil
	})
}

// managedToEntry maps a service.ManagedCert to the API CertEntry shape.
func managedToEntry(mc service.ManagedCert) CertEntry {
	status := "active"
	if mc.Role == service.RoleBackup {
		status = "backup"
	}
	return CertEntry{
		ID:            certIDFromFingerprint(mc.Info.Fingerprint),
		Role:          mc.Role,
		Status:        status,
		Source:        mc.Source,
		KMSKeyID:      mc.KMSKeyID,
		Subject:       mc.Info.Subject,
		Issuer:        mc.Info.Issuer,
		NotBefore:     mc.Info.NotBefore.Format(time.RFC3339),
		NotAfter:      mc.Info.NotAfter.Format(time.RFC3339),
		Fingerprint:   mc.Info.Fingerprint,
		DaysRemaining: mc.Info.DaysRemaining,
		IsExpired:     mc.Info.IsExpired,
		PemBase64:     mc.Info.PemBase64,
	}
}

// normalizeRole defaults an empty/unknown role to "active".
func normalizeRole(role string) string {
	if role == service.RoleBackup {
		return service.RoleBackup
	}
	return service.RoleActive
}
