# Infrastructure

Terraform configuration for deploying the Identity Federation Gateway to AWS. Uses [terraform-aws-modules](https://github.com/terraform-aws-modules) community modules.

## Resources

| File | Resources |
|------|-----------|
| `cognito.tf` | Amazon Cognito user pool, app clients, groups, Managed Login branding |
| `lambda.tf` | AWS Lambda function (ARM64 container image) |
| `api_gateway.tf` | Amazon API Gateway HTTP API, JWT authorizer, routes |
| `dynamodb.tf` | Amazon DynamoDB single-table (PAY_PER_REQUEST, KMS encryption, PITR) |
| `kms.tf` | AWS KMS keys — RSA_2048 for signing, symmetric for encryption |
| `frontend.tf` | Amazon S3 bucket, Amazon CloudFront distribution, SPA routing function |
| `waf.tf` | AWS WAF Web ACL (OWASP CRS, rate limiting, body size limits) |
| `monitoring.tf` | Amazon SNS alerts, Amazon EventBridge health check, CloudWatch alarms |
| `dns.tf` | Route53 records, ACM wildcard certificate |
| `demo_apps.tf` | Demo SAML SP and OIDC RP (Lambda + API Gateway + CloudFront each) |
| `ecr.tf` | Amazon ECR repository for gateway container image |

## Deploy

```bash
# Initialize backend (S3 state + DynamoDB locks)
terraform init -backend-config=env/dev.backend.hcl

# Plan
terraform plan -var-file=env/dev.tfvars

# Apply
terraform apply -var-file=env/dev.tfvars
```

Or use the Makefile targets from the project root:

```bash
make tf-init
make tf-plan
make deploy-dev     # Full pipeline: build, push, apply, sync frontend
```

## Environment configuration

| File | Purpose |
|------|---------|
| `env/dev.tfvars` | Variable values for the dev environment |
| `env/dev.backend.hcl` | S3 backend configuration (bucket, key) |

## Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region | `eu-north-1` |
| `environment` | `dev`, `staging`, or `prod` | — |
| `project` | Resource naming prefix | `cognito-saml-proxy` |
| `owner` | Owner tag value | — |
| `saml_entity_id` | SAML IdP entity ID | — |
| `alert_email` | Operational alert email | — |
| `image_tag` | Lambda container image tag | `latest` |
| `log_level` | Application log level | `info` |
| `custom_domain` | Custom domain for CloudFront | `""` |
