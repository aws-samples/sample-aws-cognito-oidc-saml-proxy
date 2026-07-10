variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "eu-north-1"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "project" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "cognito-saml-proxy"
}

variable "name_suffix" {
  description = "Optional suffix appended to name_prefix (after <project>-<environment>) so multiple instances can coexist in the same account without colliding on account-global names (IAM roles, S3 bucket names). Empty by default. Naming-only: it is NOT passed to the Lambda runtime, so it does not interact with the PROXY_ENVIRONMENT allowlist."
  type        = string
  default     = ""

  validation {
    condition     = can(regex("^[a-z0-9-]*$", var.name_suffix))
    error_message = "name_suffix must be lowercase alphanumeric or hyphen (it becomes part of resource names)."
  }
}

variable "owner" {
  description = "Owner tag value for resource identification"
  type        = string
}

variable "saml_entity_id" {
  description = "SAML entity ID for this proxy (e.g. https://saml.example.com)"
  type        = string
}

variable "alert_email" {
  description = "Email address for operational alerts"
  type        = string
}

variable "image_tag" {
  description = "Container image tag for the Lambda function. Human-reference / build tag only — Lambdas deploy by immutable digest via image_digests, not by this tag."
  type        = string
  default     = "latest"
}

variable "image_digests" {
  description = <<-EOT
    Per-capability container image digests (map: capability -> "sha256:..."),
    captured at build/push time. The gateway deploys each Lambda by immutable
    digest (repo_url@sha256:...) rather than by mutable tag, so a tag can never
    be re-pointed at a different image under a running function. The intended
    flow is: build -> push to the IMMUTABLE ECR repo -> capture the digest of
    each pushed image (e.g. `docker inspect --format='{{index .RepoDigests 0}}'`
    or `aws ecr describe-images --query 'imageDetails[].imageDigest'`) -> pass
    the map here on apply. Keyed by the same capability names as the Lambda
    function set (saml-sso, saml-slo, saml-metadata, oidc-authorize, oidc-token,
    oidc-discovery, management-api, health). Empty by default so `terraform
    validate`/`test` stay clean; a real apply MUST supply a digest for every
    function — the gateway fails closed (no silent fallback to a mutable tag)
    when a key is missing.
  EOT
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for d in values(var.image_digests) : can(regex("^sha256:[0-9a-f]{64}$", d))])
    error_message = "Each image_digests value must be a full image digest of the form sha256:<64 hex chars>."
  }
}

variable "state_bucket" {
  description = <<-EOT
    Name of the versioned, SSE-KMS-encrypted, public-access-blocked S3 bucket
    that holds Terraform remote state. Used by the terraform_remote_state data
    sources to read other stacks' outputs; it MUST match the `bucket` set in the
    env/*.backend.hcl used at `terraform init` for every stack. Empty by default
    so offline `terraform validate`/`test` stay clean (the data sources are not
    read then); a real cross-stack apply requires it to be set.
  EOT
  type        = string
  default     = ""
}

variable "state_bucket_region" {
  description = <<-EOT
    AWS region where the Terraform state S3 bucket resides. The state bucket may
    be in a different region than the resources being deployed (e.g. bucket in
    eu-north-1, resources in us-east-1). Defaults to var.aws_region so existing
    same-region configs need no change.
  EOT
  type        = string
  default     = ""
}

variable "lambda_reserved_concurrency" {
  description = <<-EOT
    Per-function reserved concurrency ceiling applied to every gateway Lambda
    (MF-11). Each function sits behind the same internet-reachable API
    (CloudFront -> API Gateway -> Lambda), and the unauthenticated SAML/OIDC
    routes carry no API-Gateway authorizer, so a flood of the execute-api host
    forces uncapped Lambda invocations before the edge-secret 403. Reserving a
    fixed ceiling per function bounds that blast radius as a DoS / cost ceiling
    and also guarantees each function a floor of concurrency (reserved capacity
    is not stealable by a noisy neighbour). The value reserves from the account
    concurrency pool, so total reservation is roughly this * (function count);
    keep enough unreserved headroom in the account. Set to -1 to opt out
    (unreserved) for a function-count/account that cannot spare the reservation.
  EOT
  type        = number
  default     = 50

  validation {
    condition     = var.lambda_reserved_concurrency == -1 || var.lambda_reserved_concurrency >= 1
    error_message = "lambda_reserved_concurrency must be -1 (unreserved) or a positive integer."
  }
}

variable "log_level" {
  description = "Application log level"
  type        = string
  default     = "info"

  validation {
    condition     = contains(["debug", "info", "warn", "error"], var.log_level)
    error_message = "Log level must be one of: debug, info, warn, error."
  }
}

variable "custom_domain" {
  description = "Optional custom domain for the API (leave empty to use the default API Gateway URL)"
  type        = string
  default     = ""
}

variable "dns_zone_name" {
  description = "Route53 hosted zone name for DNS records (e.g. test.example.com)"
  type        = string
  default     = ""
}

variable "demo_subdomain_prefix" {
  description = "Subdomain prefix for demo apps (e.g. 'fedgw' creates gateway.fedgw.{zone}, saml.fedgw.{zone}, oidc.fedgw.{zone})"
  type        = string
  default     = "fedgw"
}

variable "additional_tags" {
  description = "Additional tags applied to every resource via the provider default_tags. Leave empty for none. Example: {\"auto-delete\" = \"no\"} to opt out of any account auto-deletion policy your organization applies to untagged resources."
  type        = map(string)
  default     = {}
}

variable "enable_public_iac_templates" {
  description = "Attach a public-read policy to the IaC templates bucket so CloudFormation can fetch quick-create templates anonymously. Must be false in accounts that enforce account-level S3 Block Public Access."
  type        = bool
  default     = false
}

variable "ses_from_email_address" {
  description = "Verified Amazon SES identity used as the Cognito From address. When set, the user pool sends via SES (email_sending_account=DEVELOPER) instead of the rate-limited COGNITO_DEFAULT sender. Leave empty to keep COGNITO_DEFAULT. Note: while SES is in sandbox, mail is only delivered to verified recipient addresses."
  type        = string
  default     = ""
}

variable "enable_backup_signing_key" {
  description = "Create a second RSA_2048 SIGN_VERIFY KMS key to back the standby 'backup' signing certificate. Promoting the backup certificate performs a real key roll. When false, the backup certificate role reuses the primary signing key (certificate renewal only)."
  type        = bool
  default     = true
}

variable "tenant_account_ids" {
  description = <<-EOT
    Allow-list of onboarded customer AWS account IDs the management-api Lambda may
    sts:AssumeRole into (assuming the customer-side identity-gateway-<tenant> role).
    The management-api role's assume-role grant is rendered from EXACTLY this list —
    never an account wildcard. Add a tenant's 12-digit account ID here as part
    of onboarding; remove it at offboarding. The per-tenant sts:ExternalId condition on
    the customer's own trust policy remains as defense-in-depth, but the account scope
    lives in THIS account's governance rather than being delegated entirely to the far
    side of the trust relationship. When empty, no cross-account assume-role statement is
    attached at all (fail closed): cross-account probing simply does not work until an
    account is explicitly allow-listed, which is the correct default for a fresh deploy.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.tenant_account_ids : can(regex("^[0-9]{12}$", id))])
    error_message = "Each tenant_account_ids entry must be a 12-digit AWS account ID."
  }
}
