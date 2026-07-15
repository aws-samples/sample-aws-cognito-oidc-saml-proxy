# Prerequisites

Before deploying, make sure you have the following.

## Tooling

| Tool | Purpose |
|------|---------|
| AWS CLI (configured profile) | All AWS operations |
| Terraform ≥ 1.10 | Infrastructure, with native S3 state locking |
| Go (see `go.mod` for the version) | Build the Lambda binaries |
| Docker | Build and push the 8 Lambda container images |
| Node.js + npm | Build the admin console SPA |
| `jq` | Used by several `make` targets |

## AWS account

- An AWS account and credentials configured for the AWS CLI (a named profile or `default`).
- Permissions to create the resources in [Architecture](../overview/architecture.md)
  (Lambda, API Gateway, CloudFront, WAF, Cognito, DynamoDB, KMS, ECR, S3, Secrets Manager,
  SNS, EventBridge, CloudWatch).

## Terraform state backend

The three stacks (`registry`, `gateway`, `demo`) each declare an S3 backend, so an S3 state
bucket must exist **before** `terraform init` — Terraform cannot bootstrap its own backend.
Native S3 locking is used (`use_lockfile = true`), so **no DynamoDB lock table is needed**.

Create a versioned, encrypted, public-access-blocked bucket, then supply its name in your
`infra/env/<stack>.<env>.backend.hcl` files and in `dev.tfvars` (`state_bucket` /
`state_bucket_region`). See the `infra/env/*.example` templates.

Continue to the [Quickstart](quickstart.md) for the full end-to-end walkthrough.
