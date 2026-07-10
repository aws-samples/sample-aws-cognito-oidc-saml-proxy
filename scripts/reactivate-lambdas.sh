#!/usr/bin/env bash
set -euo pipefail
REG="$(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com"
REGION="us-east-1"; PROFILE="default"
PREFIX="cognito-saml-proxy-dev"

FNS="saml-sso saml-slo saml-metadata oidc-authorize oidc-token oidc-discovery management-api health demo-saml-sp demo-oidc-rp"

for fn in $FNS; do
  repo="${PREFIX}-${fn}"
  fname="${PREFIX}-${fn}"
  echo "=== nudging ${fname} ==="
  aws lambda update-function-code --function-name "$fname" \
    --image-uri "${REG}/${repo}:latest" \
    --region "$REGION" --profile "$PROFILE" --query "LastUpdateStatus" --output text || echo "  (skip ${fname})"
done
echo "ALL_NUDGED"
