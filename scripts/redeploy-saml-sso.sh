#!/usr/bin/env bash
#
# redeploy-saml-sso.sh — build, push, and roll the saml-sso Lambda image.
#
# Mirrors redeploy-management-api.sh. Used to ship Go changes that affect the
# SAML SSO path (e.g. the default-tenant seeding at startup).
#
# Config via env (defaults match the dev deployment):
#   REG      ECR registry host      (default: derived from the caller's AWS account)
#   REGION   AWS region             (default us-east-1)
#   PROFILE  AWS CLI profile        (default default)
#   PREFIX   resource name prefix   (default cognito-saml-proxy-dev)
#
set -euo pipefail

REG="${REG:-$(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com}"
REGION="${REGION:-us-east-1}"
PROFILE="${PROFILE:-default}"
PREFIX="${PREFIX:-cognito-saml-proxy-dev}"

FN="${PREFIX}-saml-sso"
REPO="${PREFIX}-saml-sso"

echo "=== login to ECR (${REG}) ==="
aws ecr get-login-password --region "$REGION" --profile "$PROFILE" | docker login --username AWS --password-stdin "$REG"

echo "=== build binary (linux/arm64) ==="
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/saml-sso ./cmd/saml-sso/

echo "=== build + push image ==="
DOCKER_BUILDKIT=0 docker build --platform linux/arm64 -t "${REPO}:latest" -f cmd/saml-sso/Dockerfile bin/
docker tag "${REPO}:latest" "${REG}/${REPO}:latest"
docker push "${REG}/${REPO}:latest"

echo "=== update lambda to new image ==="
aws lambda update-function-code --function-name "$FN" --image-uri "${REG}/${REPO}:latest" \
  --region "$REGION" --profile "$PROFILE" --query "LastUpdateStatus" --output text

echo "DONE"
