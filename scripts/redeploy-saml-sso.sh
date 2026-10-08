#!/usr/bin/env bash
#
# redeploy-saml-sso.sh — build, push, and roll the saml-sso Lambda image.
#
# Shortcut for `./scripts/redeploy-function.sh saml-sso`; see that script for
# how the image is tagged, deployed by digest, and recorded in the tfvars.
#
# Config via env: PROFILE (default), REGION (us-east-1), ENV (dev).
#
set -euo pipefail
exec "$(dirname "$0")/redeploy-function.sh" saml-sso
