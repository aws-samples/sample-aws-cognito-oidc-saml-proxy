#!/usr/bin/env bash
#
# redeploy-function.sh — build, push, and roll ONE gateway Lambda to a new image
# without a full `make deploy-dev`.
#
# The ECR repositories are IMMUTABLE and the gateway stack deploys every Lambda
# by image digest (var.image_digests), so this script:
#   1. builds the function binary and its arm64 image,
#   2. pushes it under a new, unique tag (<git-sha>-<UTC timestamp>),
#   3. points the Lambda at the pushed image by digest, and
#   4. records the digest in infra/env/<env>.tfvars (image_digests), so the next
#      `make gateway-apply` keeps this image instead of reverting it.
#
# Usage:
#   PROFILE=default REGION=us-east-1 ENV=dev ./scripts/redeploy-function.sh <function>
#
#   <function> is one of: saml-sso saml-slo saml-metadata oidc-authorize
#   oidc-token oidc-discovery management-api health
#
# Repository URLs and function names are read from the registry and gateway
# stack outputs, so both stacks must already be applied and initialized
# locally (make tf-init STACK=registry / STACK=gateway).
#
set -euo pipefail

cd "$(dirname "$0")/.."  # repo root

FUNCTIONS="saml-sso saml-slo saml-metadata oidc-authorize oidc-token oidc-discovery management-api health"
FN="${1:-}"
if [[ -z "$FN" || " $FUNCTIONS " != *" $FN "* ]]; then
  echo "usage: $0 <function>   (one of: $FUNCTIONS)" >&2
  exit 2
fi

PROFILE="${PROFILE:-default}"
REGION="${REGION:-us-east-1}"
ENV="${ENV:-dev}"
TFVARS="infra/env/${ENV}.tfvars"

for tool in aws docker go jq terraform; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: '$tool' not found on PATH" >&2; exit 1; }
done

REPO_URL="$(AWS_PROFILE="$PROFILE" terraform -chdir=infra/registry output -json ecr_repository_urls \
  | jq -r --arg k "$FN" '.[$k] // empty')"
FN_NAME="$(AWS_PROFILE="$PROFILE" terraform -chdir=infra/gateway output -json lambda_function_names \
  | jq -r --arg k "$FN" '.[$k] // empty')"
[[ -n "$REPO_URL" ]] || { echo "ERROR: no ECR repository for ${FN} in the registry stack outputs" >&2; exit 1; }
[[ -n "$FN_NAME" ]] || { echo "ERROR: no Lambda function for ${FN} in the gateway stack outputs" >&2; exit 1; }

REG="${REPO_URL%%/*}"
TAG="$(git rev-parse --short HEAD 2>/dev/null || echo dev)-$(date -u +%Y%m%d%H%M%S)"
REF="${REPO_URL}:${TAG}"

echo "=== ${FN}: ${FN_NAME} <- ${REF} (profile=${PROFILE}, region=${REGION}) ==="
aws ecr get-login-password --region "$REGION" --profile "$PROFILE" \
  | docker login --username AWS --password-stdin "$REG"

echo "--- build binary (linux/arm64) ---"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o "bin/${FN}" "./cmd/${FN}/"
echo "--- build + push image ---"
DOCKER_BUILDKIT=0 docker build --platform linux/arm64 -t "$REF" -f "cmd/${FN}/Dockerfile" bin/
docker push "$REF"

DIGEST="$(aws ecr describe-images --region "$REGION" --profile "$PROFILE" \
  --repository-name "${REPO_URL#*/}" --image-ids imageTag="$TAG" \
  --query 'imageDetails[0].imageDigest' --output text)"
[[ "$DIGEST" == sha256:* ]] || { echo "ERROR: could not read the digest of ${REF}" >&2; exit 1; }

echo "--- update ${FN_NAME} to ${DIGEST} ---"
aws lambda update-function-code --function-name "$FN_NAME" --image-uri "${REPO_URL}@${DIGEST}" \
  --region "$REGION" --profile "$PROFILE" --query 'LastUpdateStatus' --output text

# Record the digest inside the image_digests block only, so the next
# `make gateway-apply` deploys the same image.
if [[ -f "$TFVARS" ]] && awk -v fn="$FN" -v d="$DIGEST" '
    /^image_digests[[:space:]]*=/ { inb = 1 }
    inb && $0 ~ "^[[:space:]]*\"" fn "\"[[:space:]]*=" { sub(/"sha256:[0-9a-f]+"/, "\"" d "\""); found = 1 }
    inb && /^}/ { inb = 0 }
    { print }
    END { exit found ? 0 : 3 }' "$TFVARS" > "${TFVARS}.tmp"; then
  mv "${TFVARS}.tmp" "$TFVARS"
  echo "Recorded \"${FN}\" = \"${DIGEST}\" in ${TFVARS}."
else
  rm -f "${TFVARS}.tmp"
  echo "WARNING: ${TFVARS} has no image_digests entry for ${FN}. Add this line inside" >&2
  echo "         image_digests, or the next gateway apply reverts the function:" >&2
  echo "           \"${FN}\" = \"${DIGEST}\"" >&2
fi
echo "DONE"
