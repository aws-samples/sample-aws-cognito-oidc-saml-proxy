################################################################################
# DynamoDB — Single-Table Design
################################################################################

module "dynamodb" {
  source  = "terraform-aws-modules/dynamodb-table/aws"
  version = "~> 5.5"

  name      = local.name_prefix
  hash_key  = "PK"
  range_key = "SK"

  billing_mode = "PAY_PER_REQUEST"

  attributes = [
    { name = "PK", type = "S" },
    { name = "SK", type = "S" },
    { name = "GSI1PK", type = "S" },
    { name = "GSI1SK", type = "S" },
    { name = "GSI2PK", type = "S" },
    { name = "GSI2SK", type = "S" },
  ]

  global_secondary_indexes = [
    {
      name            = "entityId-index"
      hash_key        = "GSI1PK"
      range_key       = "GSI1SK"
      projection_type = "ALL"
    },
    {
      name            = "user-flow-index"
      hash_key        = "GSI2PK"
      range_key       = "GSI2SK"
      projection_type = "ALL"
    },
  ]

  ttl_attribute_name = "ttl"
  ttl_enabled        = true

  point_in_time_recovery_enabled = true

  server_side_encryption_enabled     = true
  server_side_encryption_kms_key_arn = module.kms_encryption.key_arn

  deletion_protection_enabled = var.environment == "prod"

  tags = {
    Component = "data-store"
  }
}
