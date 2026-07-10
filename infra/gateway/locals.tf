locals {
  # Single-sourced from modules/common so the registry and gateway stacks
  # cannot drift. The ~65 local.name_prefix / local.tags references across this
  # stack are unchanged — they resolve through these aliases.
  name_prefix      = module.common.name_prefix
  tags             = module.common.tags
  lambda_functions = module.common.lambda_functions

  # Resolve the base URL: custom domain if set, otherwise the CloudFront distribution URL.
  # All protocol flows (SAML, OIDC) must route through CloudFront for WAF protection.
  base_url = var.custom_domain != "" ? "https://${var.custom_domain}" : "https://${aws_cloudfront_distribution.main.domain_name}"

  # Cognito client references
  cognito_spa_client_id     = aws_cognito_user_pool_client.spa.id
  cognito_backend_client_id = aws_cognito_user_pool_client.backend.id

  # Signing key references. The backup key is optional (var.enable_backup_signing_key).
  # signing_key_arns is the set of KMS keys any signer/cert lifecycle function may
  # need access to — the primary key plus the backup key when enabled. This is the
  # set granted for Sign/GetPublicKey so that promoting a backup-key-backed cert to
  # active keeps signing working.
  backup_signing_key_id  = var.enable_backup_signing_key ? module.kms_saml_signing_backup[0].key_id : ""
  backup_signing_key_arn = var.enable_backup_signing_key ? module.kms_saml_signing_backup[0].key_arn : ""
  signing_key_arns       = compact([module.kms_saml_signing.key_arn, local.backup_signing_key_arn])
}
