################################################################################
# CloudFront Origin-Verify Edge Secret — Secrets Manager
#
# The CloudFront origin-verify secret (random_password.edge_secret, defined in
# frontend.tf) closes the API Gateway execute-api bypass by making every Lambda
# refuse requests lacking the X-Origin-Verify header. Originally the raw secret
# was delivered as a Lambda environment variable (PROXY_EDGE_AUTH_SECRET), which
# means it was visible in the Lambda console and in CloudTrail GetFunctionConfiguration
# events. Moving it to Secrets Manager removes it from the env surface; each
# function fetches the value once at cold-start startup via
# secretsmanager:GetSecretValue, and the value never appears in function config.
#
# CloudFront still references random_password.edge_secret.result directly for the
# custom_header value (frontend.tf) — it must know the raw secret to inject it.
# Both the SM version and the CloudFront header therefore derive from the same
# random_password resource, so they always agree. If the password is ever tainted
# and regenerated, a single terraform apply updates SM, CloudFront, and the Lambda
# ARN reference atomically; running Lambdas re-fetch the new value on next cold
# start (no ignore_changes unlike the binary OIDC key, because CloudFront must
# remain in sync with whatever value SM holds).
################################################################################

resource "aws_secretsmanager_secret" "edge_secret" {
  # checkov:skip=CKV2_AWS_57: Auto-rotation does not apply — this secret is
  # Terraform-managed (random_password is the source of truth). Rotation is
  # performed by tainting random_password.edge_secret and re-applying, which
  # atomically updates Secrets Manager and the CloudFront origin-verify header.
  # A Lambda rotation function would have nothing to call; the value originates
  # in Terraform, not in an external credential store.
  name        = "${local.name_prefix}-edge-secret"
  description = "CloudFront origin-verify shared secret (X-Origin-Verify header). Lambda functions fetch at cold-start; the raw value is never exposed as an env var."
  kms_key_id  = module.kms_encryption.key_id

  tags = {
    Component = "secrets"
    Purpose   = "edge-origin-verify"
  }
}

resource "aws_secretsmanager_secret_version" "edge_secret" {
  secret_id     = aws_secretsmanager_secret.edge_secret.id
  secret_string = random_password.edge_secret.result
  # No ignore_changes: CloudFront's custom_header also references
  # random_password.edge_secret.result, so both must stay in sync. A taint of the
  # random_password resource regenerates the value and a single apply updates
  # CloudFront, SM, and the Lambda ARN env var together.
}
