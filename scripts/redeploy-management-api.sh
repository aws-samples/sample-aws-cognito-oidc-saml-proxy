#!/usr/bin/env bash
set -euo pipefail

REG="$(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com"
REPO="cognito-saml-proxy-dev-management-api"
FN="cognito-saml-proxy-dev-management-api"
PROFILE="default"; REGION="us-east-1"

echo "=== login to ECR ==="
aws ecr get-login-password --region "$REGION" --profile "$PROFILE" | docker login --username AWS --password-stdin "$REG"

echo "=== build binary ==="
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/management-api ./cmd/management-api/

echo "=== build + push image ==="
DOCKER_BUILDKIT=0 docker build --platform linux/arm64 -t "${REPO}:latest" -f cmd/management-api/Dockerfile bin/
docker tag "${REPO}:latest" "${REG}/${REPO}:latest"
docker push "${REG}/${REPO}:latest"

echo "=== update lambda to new image ==="
aws lambda update-function-code --function-name "$FN" --image-uri "${REG}/${REPO}:latest" \
  --region "$REGION" --profile "$PROFILE" --query "LastUpdateStatus" --output text

echo "DONE"
