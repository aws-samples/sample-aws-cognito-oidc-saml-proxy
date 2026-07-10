#!/usr/bin/env bash
set -euo pipefail

REG="$(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com"
TAG="latest"
FUNCTIONS="saml-sso saml-slo saml-metadata oidc-authorize oidc-token oidc-discovery management-api health"

for fn in $FUNCTIONS; do
  repo="cognito-saml-proxy-dev-${fn}"
  ref="${REG}/${repo}:${TAG}"
  echo "=== ${fn}: build ${ref} ==="
  DOCKER_BUILDKIT=0 docker build --platform linux/arm64 -t "${repo}:${TAG}" -f "cmd/${fn}/Dockerfile" bin/
  docker tag "${repo}:${TAG}" "${ref}"
  echo "=== ${fn}: push ==="
  docker push "${ref}"
  echo "${fn} OK"
done
echo "ALL_FUNCTION_IMAGES_PUSHED"
