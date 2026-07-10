output "app_url" {
  description = "Public URL of the demo (CloudFront). Reachable only from allowed_cidrs."
  value       = "https://${aws_cloudfront_distribution.main.domain_name}"
}

output "bucket_name" {
  description = "S3 bucket the SPA assets are synced to."
  value       = aws_s3_bucket.frontend.id
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID (for cache invalidation)."
  value       = aws_cloudfront_distribution.main.id
}

output "waf_web_acl_arn" {
  description = "WAF web ACL guarding the distribution, or null when access is public (no allowed_cidrs)."
  value       = one(aws_wafv2_web_acl.main[*].arn)
}
