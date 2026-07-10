variable "aws_region" {
  description = "AWS region for the bucket/WAF. CloudFront-scoped WAF requires us-east-1."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for resource names (bucket, distribution, WAF)."
  type        = string
  default     = "cognito-custom-ui-demo"
}

################################################################################
# Cognito configuration rendered into /config.json (served from S3 via CloudFront).
# These are the only values needed to point the demo at your user pool. No
# secrets — the app client is public.
################################################################################

variable "cognito_user_pool_id" {
  description = "Cognito User Pool ID the demo authenticates against (e.g. us-east-1_abc123)."
  type        = string
}

variable "cognito_client_id" {
  description = "Public Cognito app client ID (no secret; USER_SRP_AUTH + REFRESH_TOKEN_AUTH)."
  type        = string
}

variable "cognito_region" {
  description = "Region of the Cognito user pool. Defaults to aws_region when empty."
  type        = string
  default     = ""
}

variable "gateway_base_url" {
  description = "Federation Gateway base URL (optional; used by the Config/Launcher pages)."
  type        = string
  default     = ""
}

variable "gateway_tenant" {
  description = "Federation Gateway tenant slug (optional)."
  type        = string
  default     = ""
}

variable "apps_json" {
  description = "JSON array of launchable apps for the App Launcher page (optional)."
  type        = string
  default     = ""
}

################################################################################
# Access control
################################################################################

variable "allowed_cidrs" {
  description = <<-EOT
    OPTIONAL IPv4 CIDRs allowed to reach the demo (e.g. ["203.0.113.7/32"]). When
    set (together with allowed_ipv6_cidrs), a CloudFront WAF restricts access to
    these CIDRs. EMPTY (the default) = no WAF, publicly reachable so customers can
    use the demo. Find your IP with: curl https://checkip.amazonaws.com
  EOT
  type        = list(string)
  default     = []
}

variable "allowed_ipv6_cidrs" {
  description = <<-EOT
    OPTIONAL IPv6 CIDRs allowed to reach the demo (e.g. ["2001:db8::/64"]). Home
    IPv6 host addresses rotate, so a /64 subnet is usually the right granularity.
    EMPTY (the default) = no IPv6 restriction.
  EOT
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
