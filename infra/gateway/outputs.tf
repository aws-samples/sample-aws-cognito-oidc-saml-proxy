################################################################################
# API Gateway
################################################################################

# Publishes the CloudFront-fronted base URL rather than the raw execute-api
# invoke_url. The raw execute-api endpoint bypasses the CloudFront WAF, so it is
# deliberately no longer exposed as a consumable output; all consumers
# must reach the API through the WAF-protected front door.
output "api_endpoint" {
  description = "Public API base URL (CloudFront-fronted, WAF-protected)"
  value       = local.base_url
}

output "api_id" {
  description = "HTTP API ID"
  value       = aws_apigatewayv2_api.main.id
}

################################################################################
# Cognito
################################################################################

output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.main.id
}

output "cognito_user_pool_endpoint" {
  description = "Cognito User Pool OIDC endpoint"
  value       = aws_cognito_user_pool.main.endpoint
}

output "cognito_spa_client_id" {
  description = "Cognito SPA client ID (public, no secret)"
  value       = local.cognito_spa_client_id
}

output "cognito_backend_client_id" {
  description = "Cognito backend client ID (confidential)"
  value       = local.cognito_backend_client_id
}

output "cognito_domain" {
  description = "Cognito hosted UI domain"
  value       = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${var.aws_region}.amazoncognito.com"
}

################################################################################
# DynamoDB
################################################################################

output "dynamodb_table_name" {
  description = "DynamoDB table name"
  value       = module.dynamodb.dynamodb_table_id
}

output "dynamodb_table_arn" {
  description = "DynamoDB table ARN"
  value       = module.dynamodb.dynamodb_table_arn
}

output "dynamodb_session_table_name" {
  description = "DynamoDB session table name"
  value       = module.dynamodb_session.dynamodb_table_id
}

output "dynamodb_session_table_arn" {
  description = "DynamoDB session table ARN"
  value       = module.dynamodb_session.dynamodb_table_arn
}

################################################################################
# KMS
################################################################################

output "kms_signing_key_arn" {
  description = "KMS SAML signing key ARN"
  value       = module.kms_saml_signing.key_arn
}

output "kms_signing_key_id" {
  description = "KMS SAML signing key ID"
  value       = module.kms_saml_signing.key_id
}

output "kms_signing_key_backup_arn" {
  description = "KMS backup SAML signing key ARN (empty when enable_backup_signing_key is false)"
  value       = local.backup_signing_key_arn
}

output "kms_signing_key_backup_id" {
  description = "KMS backup SAML signing key ID (empty when enable_backup_signing_key is false)"
  value       = local.backup_signing_key_id
}

output "kms_encryption_key_arn" {
  description = "KMS encryption key ARN"
  value       = module.kms_encryption.key_arn
}

################################################################################
# Lambda (per-capability functions)
################################################################################

output "lambda_function_names" {
  description = "Per-capability Lambda function names"
  value       = { for k, v in module.lambda_fn : k => v.lambda_function_name }
}

output "lambda_function_arns" {
  description = "Per-capability Lambda function ARNs"
  value       = { for k, v in module.lambda_fn : k => v.lambda_function_arn }
}

################################################################################
# Monitoring
################################################################################

output "sns_topic_arn" {
  description = "SNS alerts topic ARN"
  value       = module.sns_alerts.topic_arn
}

################################################################################
# CloudFront
################################################################################

output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name"
  value       = aws_cloudfront_distribution.main.domain_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.main.id
}

output "frontend_bucket_name" {
  description = "Frontend S3 bucket name"
  value       = module.frontend_s3.s3_bucket_id
}

################################################################################
# WAF
################################################################################

output "waf_web_acl_arn" {
  description = "WAFv2 CloudFront Web ACL ARN"
  value       = aws_wafv2_web_acl.main.arn
}

output "waf_regional_web_acl_arn" {
  description = "WAFv2 regional Web ACL ARN. Not associated with the HTTP API — WAFv2 cannot bind a Web ACL to an API Gateway HTTP (v2) stage; kept ready for a WAF-associable regional resource (ALB/REST API/custom-domain path). See waf.tf."
  value       = aws_wafv2_web_acl.regional.arn
}

################################################################################
# IaC Templates
################################################################################

output "iac_templates_bucket_name" {
  description = "Private S3 bucket holding rendered CFN/TF/CLI onboarding templates; served anonymously via CloudFront/OAC at <cloudfront>/templates/*, never public"
  value       = module.iac_templates_bucket.s3_bucket_id
}

output "iac_templates_bucket_arn" {
  description = "ARN of the IaC templates bucket"
  value       = module.iac_templates_bucket.s3_bucket_arn
}

output "saas_principal_role_name" {
  description = "Name of the management-api Lambda role — embedded in every tenant's generated IaC trust policy"
  value       = module.lambda_fn["management-api"].lambda_role_name
}

################################################################################
# Cross-stack outputs (consumed by the demo stack)
################################################################################

output "base_url" {
  description = "CloudFront-fronted base URL (custom domain if set, else the generated CloudFront domain). Consumed by the demo stack."
  value       = local.base_url
}

output "wildcard_cert_arn" {
  description = "Wildcard ACM certificate ARN for demo CloudFront distributions, or empty when no DNS zone is configured. Consumed by the demo stack."
  value       = local.dns_enabled ? aws_acm_certificate_validation.wildcard[0].certificate_arn : ""
}
