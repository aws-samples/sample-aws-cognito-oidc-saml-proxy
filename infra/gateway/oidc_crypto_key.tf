################################################################################
# OIDC CryptoKey — Secrets Manager (MF-5)
#
# zitadel/oidc uses a 32-byte symmetric key to encrypt opaque bearer tokens
# (AES-GCM). When the OIDC provider is split across Lambdas (oidc-authorize,
# oidc-token, oidc-discovery) every function MUST share the same key; a mismatch
# causes token decryption failures (userinfo 401) and silent revocation races.
#
# The key is:
#   - generated once by Terraform (random_bytes) as a binary secret
#   - stored in Secrets Manager as SecretBinary (never touches env vars / disk)
#   - encrypted at rest by the gateway KMS key (module.kms_encryption)
#   - rotated by updating this resource and re-running terraform apply
################################################################################

resource "random_bytes" "oidc_crypto_key" {
  length = 32
}

resource "aws_secretsmanager_secret" "oidc_crypto_key" {
  # checkov:skip=CKV2_AWS_57: Auto-rotation does not apply — this secret is
  # Terraform-managed (random_bytes is the source of truth). Rotation is performed
  # by tainting random_bytes.oidc_crypto_key and re-applying, which atomically
  # regenerates the key and updates all Lambda functions at cold-start. A Lambda
  # rotation function would have nowhere to propagate the new value; the key is
  # only consumed internally by this service's own Lambdas, which re-fetch from SM.
  name        = "${local.name_prefix}-oidc-crypto-key"
  description = "32-byte AES-GCM key shared by all OIDC Lambda functions (MF-5). Binary secret."
  kms_key_id  = module.kms_encryption.key_id

  tags = {
    Component = "secrets"
    Purpose   = "oidc-crypto-key"
  }
}

resource "aws_secretsmanager_secret_version" "oidc_crypto_key" {
  secret_id     = aws_secretsmanager_secret.oidc_crypto_key.id
  secret_binary = random_bytes.oidc_crypto_key.base64

  lifecycle {
    # Prevent Terraform from rotating the key on every apply — only change if
    # random_bytes.oidc_crypto_key changes (i.e., an explicit `taint`).
    ignore_changes = [secret_binary]
  }
}
