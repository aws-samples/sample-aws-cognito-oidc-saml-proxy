################################################################################
# Shared cookie key — Secrets Manager (M-3)
#
# The SAML and OIDC login flows carry state across requests in signed and
# encrypted cookies (saml_flow, saml_session, oidc_flow, and the __Host- login
# binding cookies). Before this secret existed, every Lambda instance derived
# its own random key at cold start via kms:GenerateDataKey, so a cookie minted
# by one instance was unreadable by every other instance — a login only worked
# when the same container happened to serve both halves of the flow.
#
# The key is:
#   - generated once by Terraform (random_bytes) as a 32-byte binary secret
#   - stored in Secrets Manager as SecretBinary (never touches env vars / disk)
#   - encrypted at rest by the gateway KMS key (module.kms_encryption)
#   - fetched at cold start by saml-sso and oidc-authorize
#     (crypto.FetchCookieKey); SignedCookie derives per-purpose HMAC and
#     AES-GCM subkeys from it
#
# Rotation: `terraform taint random_bytes.cookie_key` then `terraform apply`.
# The new value propagates to the Lambdas at their next cold start; every
# existing cookie is invalidated (its key-id prefix no longer matches) and users
# simply re-authenticate.
################################################################################

resource "random_bytes" "cookie_key" {
  length = 32
}

resource "aws_secretsmanager_secret" "cookie_key" {
  # checkov:skip=CKV2_AWS_57: Auto-rotation does not apply — this secret is
  # Terraform-managed (random_bytes is the source of truth). Rotation is performed
  # by tainting random_bytes.cookie_key and re-applying, which atomically
  # regenerates the key and updates all Lambda functions at cold-start. A Lambda
  # rotation function would have nowhere to propagate the new value; the key is
  # only consumed internally by this service's own Lambdas, which re-fetch from SM.
  name        = "${local.name_prefix}-cookie-key"
  description = "32-byte root key for signed/encrypted login cookies, shared by saml-sso and oidc-authorize (M-3). Binary secret."
  kms_key_id  = module.kms_encryption.key_id

  tags = {
    Component = "secrets"
    Purpose   = "cookie-key"
  }
}

resource "aws_secretsmanager_secret_version" "cookie_key" {
  secret_id     = aws_secretsmanager_secret.cookie_key.id
  secret_binary = random_bytes.cookie_key.base64

  lifecycle {
    # Prevent Terraform from rotating the key on every apply — only change if
    # random_bytes.cookie_key changes (i.e., an explicit `taint`).
    ignore_changes = [secret_binary]
  }
}
