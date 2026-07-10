################################################################################
# IaC Templates Bucket — private storage for CFN quick-create templates,
# served anonymously at the edge through CloudFront/OAC.
#
# CloudFormation's quick-create URL requires an unauthenticated HTTPS templateURL
# that CFN fetches server-side; signed URLs with bearer tokens fail silently.
# Rather than making the bucket public-read, the bucket stays
# PRIVATE — Block Public Access on, no public policy — and a CloudFront
# templates/* cache behavior fronts it via an Origin Access Control identity
# (see infra/frontend.tf). CFN reads templates over the CloudFront URL; the
# bucket is never public. A 24-hour lifecycle rule auto-deletes generated
# templates. Templates do NOT embed ExternalId as a literal — it is passed via
# the CFN NoEcho parameter in the quick-create URL query string.
#
# var.enable_public_iac_templates remains as a legacy escape hatch (default
# false). Leave it false: the CloudFront path serves templates without any
# public bucket policy, and most accounts enforce account-level S3 Block Public
# Access anyway.
################################################################################

module "iac_templates_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  # Matches the frontend bucket's version (frontend.tf). The 4.x line used the
  # deprecated data.aws_region.current.name attribute (removed-in-future under
  # aws provider v6); 5.11 uses .region and emits no deprecation warning.
  version = "~> 5.11"

  bucket = "${local.name_prefix}-iac-templates-${data.aws_caller_identity.current.account_id}"

  # The bucket is served anonymously through CloudFront/OAC, so it stays
  # private: keep Block Public Access on. The one exception is the legacy
  # public-read escape hatch (var.enable_public_iac_templates, default false),
  # which relaxes block_public_policy/restrict_public_buckets so a public
  # templates/* policy can attach. Leave it false — the CloudFront path needs no
  # public policy and most accounts enforce account-level S3 Block Public Access.
  block_public_acls       = true
  block_public_policy     = !var.enable_public_iac_templates
  ignore_public_acls      = true
  restrict_public_buckets = !var.enable_public_iac_templates

  # Policy is managed by the dedicated aws_s3_bucket_policy.iac_templates below
  # (grants the CloudFront OAC read on templates/*, and — only when explicitly
  # enabled — the legacy anonymous public-read statement).
  attach_policy = false

  lifecycle_rule = [
    {
      id         = "expire-templates"
      enabled    = true
      filter     = { prefix = "templates/" }
      expiration = { days = 1 }
    },
  ]

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
      bucket_key_enabled = true
    }
  }

  tags = merge(local.tags, {
    Component = "iac-templates"
  })
}

################################################################################
# IaC Templates Bucket Policy
#
# Grants the CloudFront OAC read on templates/* so the private bucket can be
# served at the edge. The aws:SourceArn condition scopes the grant to
# this distribution only; S3 Block Public Access does not treat a grant to the
# cloudfront.amazonaws.com service principal as "public", so this composes with
# Block Public Access being on (the frontend bucket uses the same pattern).
#
# When var.enable_public_iac_templates is true (legacy escape hatch, default
# false) the anonymous public-read statement is appended as well; that path
# requires Block Public Access to be relaxed on this bucket (handled above).
################################################################################

resource "aws_s3_bucket_policy" "iac_templates" {
  bucket = module.iac_templates_bucket.s3_bucket_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid       = "AllowCloudFrontOAC"
          Effect    = "Allow"
          Principal = { Service = "cloudfront.amazonaws.com" }
          Action    = "s3:GetObject"
          Resource  = "${module.iac_templates_bucket.s3_bucket_arn}/templates/*"
          Condition = {
            StringEquals = {
              "AWS:SourceArn" = aws_cloudfront_distribution.main.arn
            }
          }
        },
      ],
      var.enable_public_iac_templates ? [
        {
          Sid       = "PublicReadTemplates"
          Effect    = "Allow"
          Principal = "*"
          Action    = "s3:GetObject"
          Resource  = "${module.iac_templates_bucket.s3_bucket_arn}/templates/*"
        },
      ] : []
    )
  })
}
