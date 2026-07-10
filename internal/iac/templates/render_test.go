package templates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sampleInput is the canonical test fixture. Every test builds off this.
func sampleInput(packs ...string) Input {
	in := Input{
		TenantSlug:        "acme",
		ExternalID:        "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH",
		SaaSAccountID:     "111122223333",
		SaaSPrincipalName: "identity-gateway-management-api",
		Region:            "eu-north-1",
	}
	for _, p := range packs {
		switch p {
		case "user_directory":
			in.WantUserDirectory = true
		case "user_lifecycle":
			in.WantUserLifecycle = true
		}
	}
	return in
}

func TestRender_UnknownFormatRejected(t *testing.T) {
	_, err := Render("yaml-but-not-cfn", sampleInput())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

func TestRender_CoreOnlyCFN_ContainsExpectedStructure(t *testing.T) {
	out, err := Render("cfn", sampleInput())
	require.NoError(t, err)
	s := string(out)

	assert.Contains(t, s, "AWSTemplateFormatVersion:", "must be CFN")
	assert.Contains(t, s, "NoEcho: true", "ExternalId parameter must be NoEcho")
	assert.Contains(t, s, "identity-gateway-acme", "role name substituted")
	assert.Contains(t, s, "111122223333", "SaaS account substituted")
	assert.Contains(t, s, "identity-gateway-management-api", "SaaS principal substituted")

	assert.Contains(t, s, "cognito-idp:DescribeUserPool")
	assert.Contains(t, s, "secretsmanager:GetSecretValue")
	assert.Contains(t, s, "kms:Decrypt")
	assert.Contains(t, s, "iam:SimulatePrincipalPolicy")

	assert.NotContains(t, s, "cognito-idp:ListUsers", "user_directory pack excluded")
	assert.NotContains(t, s, "cognito-idp:AdminCreateUser", "user_lifecycle pack excluded")

	assert.Contains(t, s, "RoleArn:")
	assert.Contains(t, s, "SecretArn:")
	assert.Contains(t, s, "KmsKeyArn:")
}

func TestRender_WithUserDirectoryCFN_AddsPack(t *testing.T) {
	out, err := Render("cfn", sampleInput("user_directory"))
	require.NoError(t, err)
	s := string(out)

	assert.Contains(t, s, "cognito-idp:ListUsers", "user_directory pack included")
	assert.Contains(t, s, "cognito-idp:AdminGetUser")
	assert.NotContains(t, s, "cognito-idp:AdminCreateUser", "user_lifecycle still excluded")
}

func TestRender_WithAllPacksCFN_HasEverything(t *testing.T) {
	out, err := Render("cfn", sampleInput("user_directory", "user_lifecycle"))
	require.NoError(t, err)
	s := string(out)

	assert.Contains(t, s, "cognito-idp:ListUsers")
	assert.Contains(t, s, "cognito-idp:AdminCreateUser")
	assert.Contains(t, s, "cognito-idp:AdminDisableUser")
	assert.Contains(t, s, "CreateGroup")
}

func TestRender_Terraform_ContainsExpectedStructure(t *testing.T) {
	out, err := Render("tf", sampleInput("user_directory"))
	require.NoError(t, err)
	s := string(out)

	assert.Contains(t, s, `required_providers`, "must be Terraform")
	assert.Contains(t, s, `variable "external_id"`, "external_id variable declared")
	assert.Contains(t, s, `sensitive   = true`, "external_id variable marked sensitive")
	assert.Contains(t, s, `resource "aws_iam_role" "gateway"`, "role resource present")
	assert.Contains(t, s, `resource "aws_kms_key" "gateway"`, "KMS key resource present")
	assert.Contains(t, s, `resource "aws_iam_role_policy" "user_directory"`, "user_directory pack resource present")

	assert.NotContains(t, s, "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH",
		"ExternalID must not appear literally in the Terraform template — it's a variable")
}

func TestRender_CLI_ContainsShebangAndCoreBlocks(t *testing.T) {
	out, err := Render("cli", sampleInput())
	require.NoError(t, err)
	s := string(out)

	assert.True(t, strings.HasPrefix(s, "#!/usr/bin/env bash"), "must start with bash shebang")
	assert.Contains(t, s, "aws kms create-key")
	assert.Contains(t, s, "aws secretsmanager create-secret")
	assert.Contains(t, s, "aws iam create-role")
	assert.Contains(t, s, "aws iam put-role-policy")
	assert.Contains(t, s, "identity-gateway-core")

	// The ExternalId is the assume-role shared secret and must NOT be baked
	// into this published artifact. It is supplied at runtime via the environment,
	// aborting the script (colon-question-mark expansion) when unset/empty.
	assert.NotContains(t, s, "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH",
		"CLI artifact must not embed the real ExternalId secret")
	assert.Contains(t, s, `EXTERNAL_ID="${EXTERNAL_ID:?`,
		"EXTERNAL_ID must be a required runtime env var that fails closed when unset")
}

func TestRender_DeterministicOutput(t *testing.T) {
	a, err := Render("cfn", sampleInput("user_directory"))
	require.NoError(t, err)
	b, err := Render("cfn", sampleInput("user_directory"))
	require.NoError(t, err)
	assert.Equal(t, a, b, "render must be deterministic")
}

// TestRender_CLI_ExternalIDNeverBaked verifies the ExternalId — the cross-account
// assume-role shared secret — is never embedded in the published CLI artifact,
// regardless of which capability packs are selected. The operator supplies it at
// runtime and the script must fail closed when it is unset.
func TestRender_CLI_ExternalIDNeverBaked(t *testing.T) {
	for _, packs := range [][]string{
		nil,
		{"user_directory"},
		{"user_lifecycle"},
		{"user_directory", "user_lifecycle"},
	} {
		out, err := Render("cli", sampleInput(packs...))
		require.NoError(t, err)
		s := string(out)

		assert.NotContains(t, s, "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH",
			"the real ExternalId must never appear in the published CLI artifact (packs=%v)", packs)
		// Fail-closed runtime guard: colon-question-mark expansion aborts when unset/empty.
		assert.Contains(t, s, `EXTERNAL_ID="${EXTERNAL_ID:?`,
			"EXTERNAL_ID must be read from the environment and fail closed when unset (packs=%v)", packs)

		// Non-secret substitution fields stay baked as before.
		assert.Contains(t, s, `TENANT_SLUG="acme"`, "tenant slug still substituted (packs=%v)", packs)
		assert.Contains(t, s, "111122223333", "SaaS account still substituted (packs=%v)", packs)
		assert.Contains(t, s, "identity-gateway-management-api", "SaaS principal still substituted (packs=%v)", packs)
	}
}

// TestRender_CognitoIDPResourceScoped verifies every cognito-idp admin statement
// in all three formats is scoped to the tenant pool ARN and never uses
// Resource "*". Legitimate KMS key-policy wildcards (kms:* on the CMK) are
// deliberately not flagged.
func TestRender_CognitoIDPResourceScoped(t *testing.T) {
	cases := map[string]string{
		// format → the pool-ARN token that must appear in the cognito-idp Resource.
		"cfn": "arn:aws:cognito-idp:${AWS::Region}:${AWS::AccountId}:userpool/${UserPoolId}",
		"tf":  "local.cognito_pool_arn",
		"cli": "${COGNITO_POOL_ARN}",
	}
	for format, poolARNToken := range cases {
		// Render with both capability packs so the Admin* lifecycle statement is present.
		out, err := Render(format, sampleInput("user_directory", "user_lifecycle"))
		require.NoError(t, err, "format %s", format)
		s := string(out)

		assert.Contains(t, s, "cognito-idp:AdminCreateUser",
			"format %s must include the admin lifecycle statement under test", format)
		assert.Contains(t, s, poolARNToken,
			"format %s must scope cognito-idp to the tenant pool ARN", format)
		assertNoCognitoWildcard(t, format, s)
	}
}

// assertNoCognitoWildcard verifies that no wildcard IAM Resource ("*") is attached
// to a statement granting cognito-idp actions. It inspects the text preceding each
// wildcard Resource assignment (CFN `Resource: "*"`, HCL `Resource = "*"`, JSON
// `"Resource": "*"`) for a cognito-idp action — KMS key-policy wildcards are left
// alone because their preceding window references kms, not cognito-idp.
func assertNoCognitoWildcard(t *testing.T, format, doc string) {
	t.Helper()
	wildcard := regexp.MustCompile(`\\?"?Resource\\?"?\s*[:=]\s*\\?"\*\\?"`)
	for _, loc := range wildcard.FindAllStringIndex(doc, -1) {
		start := loc[0] - 400
		if start < 0 {
			start = 0
		}
		window := doc[start:loc[0]]
		assert.NotContains(t, window, "cognito-idp:",
			"format %s: a cognito-idp statement must not use Resource \"*\" (wildcard near %q)",
			format, doc[start:loc[1]])
	}
}

func TestRender_GoldenCoreOnlyCFN(t *testing.T) {
	out, err := Render("cfn", sampleInput())
	require.NoError(t, err)

	goldenPath := filepath.Join("testdata", "core.cfn.yaml")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
		return
	}
	want, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "run with UPDATE_GOLDEN=1 to regenerate")
	assert.Equal(t, string(want), string(out))
}

func TestRender_GoldenCoreUserDirTerraform(t *testing.T) {
	out, err := Render("tf", sampleInput("user_directory"))
	require.NoError(t, err)

	goldenPath := filepath.Join("testdata", "core+user_directory.tf.hcl")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
		return
	}
	want, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "run with UPDATE_GOLDEN=1 to regenerate")
	assert.Equal(t, string(want), string(out))
}
