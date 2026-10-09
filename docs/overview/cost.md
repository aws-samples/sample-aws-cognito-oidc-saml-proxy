# Cost estimate

The stack is serverless and scales to near-zero when idle — the only meaningful fixed cost
is AWS WAF. The table below is a rough monthly estimate for an idle to light-traffic **dev**
deployment in `eu-north-1` with the default variables (no custom domain). Traffic-driven
services (Lambda, API Gateway, CloudFront, DynamoDB) stay within or near the free tier at
low volume and scale with usage.

| Service | What is provisioned | Est. monthly (USD) |
|---------|---------------------|--------------------|
| AWS WAF | 2 web ACLs (CloudFront + regional), ~6 rules each (3 AWS managed rule groups + 3 rate-based) | ~$22 |
| AWS KMS | 3 CMKs (2× RSA-2048 SAML signing, 1× symmetric encryption) | ~$3 |
| CloudWatch Logs | ~6 log groups, 365-day retention (low ingest) | ~$1–3 |
| AWS Secrets Manager | 2 secrets (edge secret, OIDC crypto key) | ~$1 |
| Amazon ECR | 10 repositories, arm64 images (~2–3 GB stored) | ~$0.30 |
| Amazon API Gateway | 3 HTTP APIs, pay-per-request | ~$0–1 |
| Amazon CloudFront | 3 distributions, pay-per-use | ~$0–1 |
| Amazon DynamoDB | 2 on-demand tables | ~$0–1 |
| AWS Lambda | 10 functions (arm64), pay-per-request | ~$0 (free tier) |
| Amazon Cognito | 1 user pool | ~$0 (≤50k MAU free) |
| Amazon Route 53 | hosted zone (only if `custom_domain` is set) | $0 (default off) |
| **Baseline (idle)** | | **~$28–35 / month** |

!!! note
    These figures are a rough estimate derived from the resources in `infra/`, not a live
    pricing run. Actual cost varies by region, traffic, and variable overrides. WAF (~$22/mo)
    dominates the fixed cost; deleting the unassociated regional web ACL roughly halves the
    WAF line if you do not plan to bind it.

## Generate a precise estimate with Infracost

[Infracost](https://github.com/infracost/infracost) produces an authoritative,
region-accurate breakdown from the Terraform itself. A repo-level `infracost.yml` is
included that covers all three stacks:

```bash
# One-time: install the CLI and get a free API key
brew install infracost         # or see https://www.infracost.io/docs
infracost auth login

# Combined monthly estimate across registry + gateway + demo
infracost breakdown --config-file infracost.yml
```

This uses the same `env/dev.tfvars` as `make deploy-dev`, so the estimate tracks your actual
variable values.
