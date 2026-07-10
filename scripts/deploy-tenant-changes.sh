#!/usr/bin/env bash
#
# deploy-tenant-changes.sh — orchestrate the deployment of the tenant-switcher /
# default-tenant changes to AWS, one phase at a time with confirmation gates.
#
# Phases (each is opt-in and prompts before doing anything that touches AWS):
#   1. Lambda code   — rebuild + roll the management-api and saml-sso images
#                      (Go changes: default-tenant seeding, default fallback,
#                      X-Tenant-Id override, DeleteTenant).
#   2. Terraform     — apply infra changes (API Gateway CORS x-tenant-id,
#                      Cognito backend-client callback URLs, demo-app env).
#                      ALWAYS plans first and requires you to type "apply".
#   3. Frontend      — build the SPA (tenant switcher) and deploy to S3+CloudFront.
#   4. Cognito users — migrate custom:tenant_id demo -> default (dry-run unless
#                      MIGRATE_APPLY=true).
#
# Usage:
#   PROFILE=default REGION=us-east-1 ./scripts/deploy-tenant-changes.sh \
#       [--code] [--infra] [--frontend] [--migrate] [--all] [--yes]
#
#   --code       run phase 1 (Lambda code)
#   --infra      run phase 2 (Terraform)
#   --frontend   run phase 3 (frontend)
#   --migrate    run phase 4 (Cognito user migration)
#   --all        run phases 1-3 (NOT migrate — that stays explicit)
#   --yes        skip the per-phase yes/no prompts (Terraform apply still
#                requires typing "apply"; migration still honors MIGRATE_APPLY)
#
# Env:
#   PROFILE (default), REGION (us-east-1), REG (dev ECR host), PREFIX
#   (cognito-saml-proxy-dev), TFVARS (env/dev.tfvars), USER_POOL_ID (phase 4),
#   MIGRATE_APPLY (false — set true to actually write user attributes).
#
set -euo pipefail

cd "$(dirname "$0")/.."  # repo root

PROFILE="${PROFILE:-default}"
REGION="${REGION:-us-east-1}"
REG="${REG:-$(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com}"
PREFIX="${PREFIX:-cognito-saml-proxy-dev}"
TFVARS="${TFVARS:-env/dev.tfvars}"
MIGRATE_APPLY="${MIGRATE_APPLY:-false}"
STATE_DIR="${STATE_DIR:-deploy-state}"

# Lambdas whose behavior changes with the tenant work (rebuilt/rolled together).
CODE_FNS="management-api saml-sso"

DO_CODE=false DO_INFRA=false DO_FRONTEND=false DO_MIGRATE=false DO_ROLLBACK_CODE=false ASSUME_YES=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --code) DO_CODE=true; shift ;;
    --infra) DO_INFRA=true; shift ;;
    --frontend) DO_FRONTEND=true; shift ;;
    --migrate) DO_MIGRATE=true; shift ;;
    --rollback-code) DO_ROLLBACK_CODE=true; shift ;;
    --all) DO_CODE=true; DO_INFRA=true; DO_FRONTEND=true; shift ;;
    --yes) ASSUME_YES=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if ! $DO_CODE && ! $DO_INFRA && ! $DO_FRONTEND && ! $DO_MIGRATE && ! $DO_ROLLBACK_CODE; then
  echo "Nothing to do. Pass one of --code --infra --frontend --migrate --rollback-code (or --all)." >&2
  exit 2
fi

confirm() {
  $ASSUME_YES && return 0
  read -r -p "$1 [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]]
}

require() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found on PATH" >&2; exit 1; }; }

echo "=== Verifying AWS identity (profile=${PROFILE}, region=${REGION}) ==="
require aws
aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" \
  --query '{Account:Account,Arn:Arn}' --output table
echo "Review the account/role above. This targets the '${PREFIX}' deployment."
confirm "Proceed against this AWS identity?" || { echo "Aborted."; exit 1; }

# ---------------------------------------------------------------------------
# Rollback code — re-point Lambdas at the image digests captured before the
# last --code deploy (deploy-state/<fn>.prev). Runs exclusively.
# ---------------------------------------------------------------------------
if $DO_ROLLBACK_CODE; then
  echo
  echo "=== Rollback: restore previous Lambda images for: ${CODE_FNS} ==="
  missing=false
  for fn in $CODE_FNS; do
    if [[ ! -s "${STATE_DIR}/${fn}.prev" ]]; then
      echo "  ERROR: no saved image for ${fn} at ${STATE_DIR}/${fn}.prev" >&2
      missing=true
    fi
  done
  $missing && { echo "Cannot roll back without saved images (run --code first)."; exit 1; }
  for fn in $CODE_FNS; do
    fname="${PREFIX}-${fn}"; prev="$(cat "${STATE_DIR}/${fn}.prev")"
    echo "  - ${fname} -> ${prev}"
  done
  confirm "Re-point the above Lambdas to their previous images?" || { echo "Aborted."; exit 1; }
  for fn in $CODE_FNS; do
    fname="${PREFIX}-${fn}"; prev="$(cat "${STATE_DIR}/${fn}.prev")"
    aws lambda update-function-code --function-name "$fname" --image-uri "$prev" \
      --region "$REGION" --profile "$PROFILE" --query "LastUpdateStatus" --output text
  done
  echo "Code rollback complete."
  exit 0
fi

# ---------------------------------------------------------------------------
# Phase 1 — Lambda code
# ---------------------------------------------------------------------------
if $DO_CODE; then
  require go; require docker
  echo
  echo "=== Phase 1: Lambda code — will rebuild and roll: ${CODE_FNS} ==="
  if confirm "Build, push, and update-function-code for these Lambdas?"; then
    mkdir -p "$STATE_DIR"
    echo "--- ECR login (${REG}) ---"
    aws ecr get-login-password --region "$REGION" --profile "$PROFILE" \
      | docker login --username AWS --password-stdin "$REG"
    for fn in $CODE_FNS; do
      repo="${PREFIX}-${fn}"; fname="${PREFIX}-${fn}"; ref="${REG}/${repo}:latest"

      # Capture the currently-deployed image (digest-pinned) for rollback,
      # BEFORE we overwrite the :latest tag. Skipped if the function is new.
      cur="$(aws lambda get-function --function-name "$fname" \
        --region "$REGION" --profile "$PROFILE" \
        --query 'Code.ImageUri' --output text 2>/dev/null || true)"
      if [[ -n "$cur" && "$cur" != "None" ]]; then
        echo "$cur" > "${STATE_DIR}/${fn}.prev"
        echo "--- ${fn}: saved current image for rollback (${STATE_DIR}/${fn}.prev) ---"
      fi

      echo "--- ${fn}: build binary ---"
      CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o "bin/${fn}" "./cmd/${fn}/"
      echo "--- ${fn}: build + push image ---"
      DOCKER_BUILDKIT=0 docker build --platform linux/arm64 -t "${repo}:latest" -f "cmd/${fn}/Dockerfile" bin/
      docker tag "${repo}:latest" "${ref}"
      docker push "${ref}"
      echo "--- ${fn}: update lambda ---"
      aws lambda update-function-code --function-name "$fname" --image-uri "${ref}" \
        --region "$REGION" --profile "$PROFILE" --query "LastUpdateStatus" --output text
    done
    echo "Phase 1 complete. Roll back with: ./scripts/deploy-tenant-changes.sh --rollback-code"
  else
    echo "Skipped phase 1."
  fi
fi

# ---------------------------------------------------------------------------
# Phase 2 — Terraform (plan first, explicit apply)
# ---------------------------------------------------------------------------
if $DO_INFRA; then
  require terraform
  echo
  echo "=== Phase 2: Terraform — planning infra changes (var-file=${TFVARS}) ==="
  ( cd infra && AWS_PROFILE="$PROFILE" terraform plan -var-file="$TFVARS" )
  echo
  echo "!!! REVIEW THE PLAN ABOVE CAREFULLY !!!"
  echo "Expected: API Gateway CORS (+x-tenant-id), Cognito backend-client callback"
  echo "URLs (/t/default/...), and demo-app env vars. If the plan wants to REPLACE"
  echo "the Cognito user pool, STOP — that destroys all users."
  read -r -p "Type 'apply' to apply this Terraform plan: " tfans
  if [[ "$tfans" == "apply" ]]; then
    ( cd infra && AWS_PROFILE="$PROFILE" terraform apply -var-file="$TFVARS" )
    echo "Phase 2 complete."
  else
    echo "Skipped Terraform apply."
  fi
fi

# ---------------------------------------------------------------------------
# Phase 3 — Frontend
# ---------------------------------------------------------------------------
if $DO_FRONTEND; then
  echo
  echo "=== Phase 3: Frontend — build SPA and deploy to S3 + invalidate CloudFront ==="
  if confirm "Run 'make frontend-deploy' (AWS_PROFILE=${PROFILE})?"; then
    make frontend-deploy AWS_PROFILE="$PROFILE" AWS_REGION="$REGION"
    echo "Phase 3 complete."
  else
    echo "Skipped phase 3."
  fi
fi

# ---------------------------------------------------------------------------
# Phase 4 — Cognito user migration
# ---------------------------------------------------------------------------
if $DO_MIGRATE; then
  echo
  echo "=== Phase 4: Cognito user migration (demo -> default) ==="
  if [[ -z "${USER_POOL_ID:-}" ]]; then
    echo "ERROR: set USER_POOL_ID to run the migration (e.g. USER_POOL_ID=us-east-1_abc123)." >&2
    exit 2
  fi
  DRY="--dry-run"
  [[ "$MIGRATE_APPLY" == "true" ]] && DRY=""
  echo "Running migration (${DRY:---apply}) against pool ${USER_POOL_ID}..."
  PROFILE="$PROFILE" REGION="$REGION" USER_POOL_ID="$USER_POOL_ID" BACKUP_DIR="$STATE_DIR" \
    ./scripts/migrate-default-tenant.sh $DRY
  [[ -n "$DRY" ]] && echo "Dry-run only. Re-run with MIGRATE_APPLY=true to write attributes (a backup file is written for rollback)."
fi

echo
echo "=== deploy-tenant-changes.sh finished ==="
