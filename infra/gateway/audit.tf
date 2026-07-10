################################################################################
# CloudWatch Logs — Audit Trail
################################################################################

resource "aws_cloudwatch_log_group" "audit" {
  name              = "/identity-gateway/audit"
  retention_in_days = 365

  kms_key_id = module.kms_encryption.key_arn

  tags = merge(local.tags, {
    Component = "audit"
  })
}
