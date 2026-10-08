#!/usr/bin/env bash
#
# redeploy-management-api.sh — build, push, and roll the management-api Lambda image.
#
# Shortcut for `./scripts/redeploy-function.sh management-api`; see that script
# for how the image is tagged, deployed by digest, and recorded in the tfvars.
#
# Config via env: PROFILE (default), REGION (us-east-1), ENV (dev).
#
set -euo pipefail
exec "$(dirname "$0")/redeploy-function.sh" management-api
