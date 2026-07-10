################################################################################
# ECR Repositories (one per gateway function)
################################################################################

module "ecr_fn" {
  source  = "terraform-aws-modules/ecr/aws"
  version = "~> 2.4"

  for_each = local.lambda_functions

  repository_name = "${local.name_prefix}-${each.key}"

  repository_image_tag_mutability = "IMMUTABLE"

  repository_image_scan_on_push = true

  # Allow the Lambda service to pull this image on (re)activation. ARN is
  # constructed (not a live ref) to avoid a cross-stack dependency on the
  # gateway's lambda_fn module that consumes this repository.
  repository_lambda_read_access_arns = [
    "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-${each.key}",
  ]

  repository_lifecycle_policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })

  repository_force_delete = var.environment != "prod"

  tags = {
    Component = "container-registry"
    Function  = each.key
  }
}
