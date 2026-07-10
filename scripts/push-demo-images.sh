#!/usr/bin/env bash
set -euo pipefail

REG="$(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com"
TAG="latest"

# name:dir:repo triples
build_push() {
  local name="$1" dir="$2" repo="$3"
  local ref="${REG}/${repo}:${TAG}"
  echo "=== ${name}: go build ==="
  ( cd "${dir}" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o "${name}" . )
  echo "=== ${name}: docker build ${ref} ==="
  DOCKER_BUILDKIT=0 docker build --platform linux/arm64 -t "${repo}:${TAG}" -f "${dir}/Dockerfile" "${dir}"
  docker tag "${repo}:${TAG}" "${ref}"
  echo "=== ${name}: push ==="
  docker push "${ref}"
  echo "${name} OK"
}

build_push "test-sp" "scripts/test-sp" "cognito-saml-proxy-dev-demo-saml-sp"
build_push "test-rp" "scripts/test-rp" "cognito-saml-proxy-dev-demo-oidc-rp"
echo "ALL_DEMO_IMAGES_PUSHED"
