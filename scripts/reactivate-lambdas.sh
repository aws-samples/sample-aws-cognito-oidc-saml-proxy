#!/usr/bin/env bash
#
# reactivate-lambdas.sh — re-apply each gateway and demo Lambda's CURRENT image,
# so a container-image function that went Inactive is optimized (re-pulled from
# ECR) again before the next request.
#
# Functions deploy by image digest, so this re-points each one at the digest it
# already runs; it never switches images. If that image has expired from ECR
# (the lifecycle policy keeps the last 10), push new images with
# `make push-function-images` and run `make gateway-apply` instead.
#
# Config via env: PROFILE (default), REGION (us-east-1),
#                 PREFIX (cognito-saml-proxy-dev, i.e. <project>-<environment>).
#
set -euo pipefail
PROFILE="${PROFILE:-default}"
REGION="${REGION:-us-east-1}"
PREFIX="${PREFIX:-cognito-saml-proxy-dev}"
FNS="saml-sso saml-slo saml-metadata oidc-authorize oidc-token oidc-discovery management-api health demo-saml-sp demo-oidc-rp"

for fn in $FNS; do
  fname="${PREFIX}-${fn}"
  uri="$(aws lambda get-function --function-name "$fname" --region "$REGION" --profile "$PROFILE" \
    --query 'Code.ImageUri' --output text 2>/dev/null || true)"
  if [[ -z "$uri" || "$uri" == "None" ]]; then
    echo "  (skip ${fname}: not found)"
    continue
  fi
  echo "=== ${fname} -> ${uri} ==="
  aws lambda update-function-code --function-name "$fname" --image-uri "$uri" \
    --region "$REGION" --profile "$PROFILE" --query "LastUpdateStatus" --output text \
    || echo "  (failed ${fname})"
done
echo "ALL_NUDGED"
