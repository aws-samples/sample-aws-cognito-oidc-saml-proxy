################################################################################
# KMS — SAML Signing Key (RSA_2048 SIGN_VERIFY)
#
# Per-Tenant KMS Keys:
# Premium tenants can have their own KMS signing keys for SAML assertion signing.
# Per-tenant keys are provisioned dynamically via the management API (POST/PUT
# /api/v1/tenants/{slug} with kmsKeyId and kmsKeyArn fields) rather than through
# Terraform. The Lambda execution role must have kms:Sign and kms:GetPublicKey
# permissions on any per-tenant keys.
#
# To provision a per-tenant key:
# 1. Create an RSA_2048 SIGN_VERIFY KMS key (manually or via a separate stack)
# 2. Grant the Lambda role kms:Sign + kms:GetPublicKey on the new key
# 3. Update the tenant via API: PUT /api/v1/tenants/{slug}
#    { "kmsKeyId": "key-id", "kmsKeyArn": "arn:aws:kms:..." }
#
# The application caches per-tenant signers in memory (sync.Map) so key
# creation only happens once per Lambda cold start per tenant.
################################################################################

module "kms_saml_signing" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 4.2"

  description              = "SAML assertion signing key for ${local.name_prefix}"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
  enable_key_rotation      = false # Not supported for asymmetric keys

  aliases = ["saml-proxy/${var.environment}/signing"]

  # Lambda access granted via IAM policies in lambda_functions.tf (per-capability
  # least-privilege). The default key policy grants the account root full access,
  # which allows IAM-based authorization to work without explicit key_statements.

  tags = {
    Component = "saml-signing"
  }
}

################################################################################
# KMS — Backup SAML Signing Key (RSA_2048 SIGN_VERIFY)
#
# Backs the standby "backup" signing certificate so promoting it performs a real
# key roll (a distinct private key), not just a certificate renewal. Created only
# when var.enable_backup_signing_key is true. Like the primary signing key,
# asymmetric keys cannot be auto-rotated; rollover happens at the certificate
# layer (generate CSR for this key -> CA signs -> import -> promote).
################################################################################

module "kms_saml_signing_backup" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 4.2"

  count = var.enable_backup_signing_key ? 1 : 0

  description              = "Backup SAML assertion signing key for ${local.name_prefix}"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
  enable_key_rotation      = false # Not supported for asymmetric keys

  aliases = ["saml-proxy/${var.environment}/signing-backup"]

  tags = {
    Component = "saml-signing-backup"
  }
}

################################################################################
# KMS — Encryption Key (Symmetric ENCRYPT_DECRYPT)
################################################################################

module "kms_encryption" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 4.2"

  description         = "Encryption key for ${local.name_prefix}"
  key_usage           = "ENCRYPT_DECRYPT"
  enable_key_rotation = true

  aliases = ["saml-proxy/${var.environment}/encryption"]

  # Lambda access granted via IAM policies in lambda_functions.tf (per-capability
  # least-privilege). The default key policy grants the account root full access,
  # which allows IAM-based authorization to work without explicit key_statements.
  key_statements = [
    {
      sid    = "AllowCloudWatchLogs"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["logs.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:CreateGrant",
        "kms:DescribeKey",
      ]
      resources = ["*"]
      conditions = [
        {
          test     = "ArnLike"
          variable = "kms:EncryptionContext:aws:logs:arn"
          values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
        }
      ]
    }
  ]

  tags = {
    Component = "encryption"
  }
}
