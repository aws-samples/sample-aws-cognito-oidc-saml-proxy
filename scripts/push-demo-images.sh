#!/usr/bin/env bash
#
# push-demo-images.sh — build and push the demo SAML SP and OIDC RP images.
#
# Wrapper around `make push-demo-images`, which reads the demo repository URLs
# from the registry stack and tags each image with the git commit (the ECR
# repositories are immutable).
#
# Config via env: PROFILE (default), REGION (us-east-1), ENV (dev).
#
set -euo pipefail
cd "$(dirname "$0")/.."  # repo root
exec make push-demo-images \
  AWS_PROFILE="${PROFILE:-default}" AWS_REGION="${REGION:-us-east-1}" ENV="${ENV:-dev}"
