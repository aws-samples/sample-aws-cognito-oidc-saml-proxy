################################################################################
# ECR — Demo App Repositories
################################################################################

module "ecr_demo_saml" {
  source  = "terraform-aws-modules/ecr/aws"
  version = "~> 2.4"

  repository_name                 = "${local.name_prefix}-demo-saml-sp"
  repository_image_tag_mutability = "IMMUTABLE"
  repository_image_scan_on_push   = true
  repository_force_delete         = var.environment != "prod"

  repository_lambda_read_access_arns = [
    "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-demo-saml-sp",
  ]

  repository_lifecycle_policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 5 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 5 }
      action       = { type = "expire" }
    }]
  })

  tags = { Component = "demo-saml-sp" }
}

module "ecr_demo_oidc" {
  source  = "terraform-aws-modules/ecr/aws"
  version = "~> 2.4"

  repository_name                 = "${local.name_prefix}-demo-oidc-rp"
  repository_image_tag_mutability = "IMMUTABLE"
  repository_image_scan_on_push   = true
  repository_force_delete         = var.environment != "prod"

  repository_lambda_read_access_arns = [
    "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-demo-oidc-rp",
  ]

  repository_lifecycle_policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 5 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 5 }
      action       = { type = "expire" }
    }]
  })

  tags = { Component = "demo-oidc-rp" }
}
