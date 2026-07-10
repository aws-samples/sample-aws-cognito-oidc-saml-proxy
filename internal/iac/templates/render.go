// Package templates renders Identity Gateway onboarding IaC artifacts
// (CloudFormation, Terraform, AWS CLI) from embedded text/template sources.
//
// The same package owns both the .tmpl source files (via embed.FS) and the
// Input struct that drives substitution, so changes to the template syntax
// stay in lockstep with the Go-side contract.
package templates

import (
	"bytes"
	"embed"
	"fmt"
	"text/template"
)

//go:embed cfn.yaml.tmpl tf.hcl.tmpl cli.sh.tmpl
var sources embed.FS

// Input drives template rendering. All fields are required except the
// WantUserDirectory / WantUserLifecycle flags which default to false.
type Input struct {
	TenantSlug        string
	ExternalID        string // the SaaS-generated value; embedded in CLI only
	SaaSAccountID     string // e.g. "111122223333"
	SaaSPrincipalName string // e.g. "identity-gateway-management-api"
	Region            string // AWS region where the customer is provisioning
	WantUserDirectory bool
	WantUserLifecycle bool
}

// templateFiles maps a format identifier to the embedded template filename.
var templateFiles = map[string]string{
	"cfn": "cfn.yaml.tmpl",
	"tf":  "tf.hcl.tmpl",
	"cli": "cli.sh.tmpl",
}

// Render returns the rendered IaC artifact for the given format.
//
// Format is one of "cfn" (CloudFormation), "tf" (Terraform), "cli" (AWS CLI).
// An unknown format returns an error. The output is deterministic for a given
// input — golden-file tests rely on this.
func Render(format string, input Input) ([]byte, error) {
	fn, ok := templateFiles[format]
	if !ok {
		return nil, fmt.Errorf("iac/templates: unknown format %q", format)
	}
	raw, err := sources.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("iac/templates: read %q: %w", fn, err)
	}
	tmpl, err := template.New(fn).Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("iac/templates: parse %q: %w", fn, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, input); err != nil {
		return nil, fmt.Errorf("iac/templates: execute %q: %w", fn, err)
	}
	return buf.Bytes(), nil
}
