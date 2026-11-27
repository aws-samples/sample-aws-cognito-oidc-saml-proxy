# Infrastructure

Terraform configuration for deploying the Identity Federation Gateway to AWS. Uses
[terraform-aws-modules](https://github.com/terraform-aws-modules) community modules.

The infrastructure is split into three stacks, each with its own state. They share one
set of input variables: `infra/variables.tf`, symlinked into each stack as `variables.tf`.

| Stack | Contents | Reads state from |
|-------|----------|------------------|
| `registry/` | Amazon ECR repositories: one per gateway Lambda function, plus the two demo apps | — |
| `gateway/` | The gateway itself (see the file table below) | `registry` |
| `demo/` | Demo SAML SP and OIDC RP (AWS Lambda + Amazon API Gateway + Amazon CloudFront each) | `registry`, `gateway` |

Apply order is fixed: `registry` → push images → `gateway` → `demo`. Destroy in reverse.

## Gateway stack files

| File | Resources |
|------|-----------|
| `cognito.tf` | Amazon Cognito user pool (Plus tier, MFA on, admin-create-only), app clients, `Admins`/`Operators` groups, Managed Login branding |
| `lambda_functions.tf` | 8 AWS Lambda functions (arm64 container images, deployed by digest) |
| `api_gateway.tf` | Amazon API Gateway HTTP API, Cognito JWT authorizer for `/api/v1/*`, SAML and OIDC routes |
| `dynamodb.tf`, `dynamodb_session.tf` | Amazon DynamoDB config table and session table (on-demand, KMS encryption, TTL) |
| `kms.tf` | AWS KMS keys: RSA_2048 signing key, optional backup signing key, symmetric encryption key |
| `oidc_crypto_key.tf`, `cookie_key.tf`, `edge_secret.tf` | AWS Secrets Manager secrets: the OIDC AES-GCM key, the login cookie key, and the CloudFront origin-verify secret |
| `frontend.tf`, `cloudfront_headers.tf` | Amazon S3 console bucket, Amazon CloudFront distribution, response headers policy (CSP) |
| `waf.tf` | AWS WAF web ACL for CloudFront, and a regional web ACL that is created but not associated (managed rule sets, rate limits) |
| `monitoring.tf`, `audit.tf`, `cert_rotation.tf` | Amazon SNS alerts, Amazon EventBridge health schedule, Amazon CloudWatch alarms and audit log group |
| `iac_templates_bucket.tf` | S3 bucket for generated onboarding IaC templates |
| `dns.tf` | Optional Amazon Route 53 records and ACM certificate (custom domains) |
| `tests/` | Offline `terraform test` hardening checks (mock provider, no AWS credentials) |

## Deploy

Use the Makefile targets from the repository root:

```bash
make deploy-dev ENV=dev AWS_PROFILE=<profile> AWS_REGION=<region>
```

Or per stack:

```bash
make tf-init STACK=gateway ENV=dev AWS_PROFILE=<profile>
make tf-plan STACK=gateway ENV=dev AWS_PROFILE=<profile>
```

See [docs/deployment/quickstart.md](../docs/deployment/quickstart.md) for prerequisites
(including the S3 state bucket), configuration, and post-install steps.

## Environment configuration

| File | Purpose |
|------|---------|
| `env/<env>.tfvars` | Variable values shared by all three stacks |
| `env/<stack>.<env>.backend.hcl` | S3 backend configuration for one stack (bucket, key, region) |

Both are gitignored; copy them from the `*.example` templates in `env/`.

## Key variables

| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region | `eu-north-1` |
| `environment` | `dev`, `staging`, or `prod` | — |
| `project` | Resource naming prefix | `cognito-saml-proxy` |
| `owner` | Owner tag value | — |
| `saml_entity_id` | SAML IdP entity ID | — |
| `alert_email` | Operational alert email | — |
| `state_bucket` | S3 bucket holding every stack's state (for cross-stack reads) | `""` (required to apply) |
| `image_digests` | Per-function image digests, written by `make push-function-images` | `{}` (required to apply) |
| `lambda_reserved_concurrency` | Reserved concurrency per function (`-1` to opt out) | `50` |
| `enable_backup_signing_key` | Create a second RSA signing key for real key rolls | `true` |
| `log_level` | Application log level | `info` |
| `custom_domain` | Custom domain for CloudFront | `""` |

The full list, with descriptions, is in [`variables.tf`](variables.tf).
