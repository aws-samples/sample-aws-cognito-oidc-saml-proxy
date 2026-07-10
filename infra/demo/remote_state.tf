# Reads the registry (demo ECR repo URLs) and gateway (base_url, wildcard cert)
# stacks. Apply order: registry -> gateway -> demo.
#
# Uses the S3 backend (same versioned, SSE-KMS-encrypted, public-access-blocked
# bucket the stacks write their own state to). var.state_bucket must match the
# `bucket` in the env/*.backend.hcl used at init; the keys mirror each stack's
# own backend key convention (<env>/<stack>/terraform.tfstate).
data "terraform_remote_state" "registry" {
  backend = "s3"

  config = {
    bucket = var.state_bucket
    key    = "${var.environment}/registry/terraform.tfstate"
    region = var.state_bucket_region != "" ? var.state_bucket_region : var.aws_region
  }
}

data "terraform_remote_state" "gateway" {
  backend = "s3"

  config = {
    bucket = var.state_bucket
    key    = "${var.environment}/gateway/terraform.tfstate"
    region = var.state_bucket_region != "" ? var.state_bucket_region : var.aws_region
  }
}
