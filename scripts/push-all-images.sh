#!/usr/bin/env bash
#
# push-all-images.sh — build and push all 8 gateway Lambda images.
#
# Wrapper around `make push-function-images`, which tags each image with the git
# commit (the ECR repositories are immutable) and writes every image digest to
# infra/env/<env>.tfvars for the next `make gateway-apply`.
#
# Config via env: PROFILE (default), REGION (us-east-1), ENV (dev).
#
set -euo pipefail
cd "$(dirname "$0")/.."  # repo root
exec make push-function-images \
  AWS_PROFILE="${PROFILE:-default}" AWS_REGION="${REGION:-us-east-1}" ENV="${ENV:-dev}"
