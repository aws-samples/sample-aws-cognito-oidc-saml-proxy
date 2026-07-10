################################################################################
# DynamoDB — Session Table (Transient State)
################################################################################

module "dynamodb_session" {
  source  = "terraform-aws-modules/dynamodb-table/aws"
  version = "~> 5.5"

  name      = "${local.name_prefix}-session"
  hash_key  = "PK"
  range_key = "SK"

  billing_mode = "PAY_PER_REQUEST"

  attributes = [
    { name = "PK", type = "S" },
    { name = "SK", type = "S" },
  ]

  ttl_attribute_name = "ttl"
  ttl_enabled        = true

  server_side_encryption_enabled     = true
  server_side_encryption_kms_key_arn = module.kms_encryption.key_arn

  deletion_protection_enabled = false

  tags = {
    Component = "session-store"
  }
}
