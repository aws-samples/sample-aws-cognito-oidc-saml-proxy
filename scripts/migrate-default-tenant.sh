#!/usr/bin/env bash
#
# migrate-default-tenant.sh
#
# Migrates an existing deployment from the legacy "demo" tenant to the built-in
# "default" tenant introduced alongside the tenant-switcher work, and supports a
# clean, exact rollback.
#
# Modes:
#   (migrate, default) Rewrites every Cognito user's custom:tenant_id from
#     "demo" (or empty) to "default". Before writing, it snapshots each changed
#     user's PRIOR value to a timestamped backup file so the change can be
#     reversed precisely.
#   (--restore FILE)   Reads a backup file and restores each user's
#     custom:tenant_id to its recorded prior value (deleting the attribute for
#     users whose prior value was empty).
#
# The gateway seeds the "default" tenant automatically at service startup, so
# you do not need to create it manually. Applications and identity sources are
# NOT moved by this script (see the closing note).
#
# Usage:
#   # Preview (no writes, no backup):
#   PROFILE=default REGION=us-east-1 USER_POOL_ID=us-east-1_xxxx \
#     ./scripts/migrate-default-tenant.sh --dry-run
#
#   # Apply (writes a backup file, then updates users):
#   PROFILE=default REGION=us-east-1 USER_POOL_ID=us-east-1_xxxx \
#     ./scripts/migrate-default-tenant.sh
#
#   # Roll back using the backup file printed by the apply run:
#   PROFILE=default REGION=us-east-1 USER_POOL_ID=us-east-1_xxxx \
#     ./scripts/migrate-default-tenant.sh --restore deploy-state/tenant-migration-backup-<ts>.tsv
#
# The backup file is tab-separated: "<username>\t<old_tenant_id>" (empty old
# value = attribute was unset).
#
set -euo pipefail

PROFILE="${PROFILE:-default}"
REGION="${REGION:-us-east-1}"
USER_POOL_ID="${USER_POOL_ID:-}"
BACKUP_DIR="${BACKUP_DIR:-deploy-state}"
FROM_TENANT="demo"
TO_TENANT="default"
DRY_RUN="false"
RESTORE_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM_TENANT="$2"; shift 2 ;;
    --to) TO_TENANT="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift ;;
    --restore) RESTORE_FILE="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$USER_POOL_ID" ]]; then
  echo "ERROR: USER_POOL_ID env var is required (e.g. USER_POOL_ID=us-east-1_abc123)." >&2
  exit 2
fi

set_tenant() { # username value
  aws cognito-idp admin-update-user-attributes \
    --user-pool-id "$USER_POOL_ID" --username "$1" \
    --user-attributes "Name=custom:tenant_id,Value=$2" \
    --region "$REGION" --profile "$PROFILE" --no-cli-pager
}

clear_tenant() { # username
  aws cognito-idp admin-delete-user-attributes \
    --user-pool-id "$USER_POOL_ID" --username "$1" \
    --user-attribute-names "custom:tenant_id" \
    --region "$REGION" --profile "$PROFILE" --no-cli-pager
}

# --------------------------------------------------------------------------
# Restore mode
# --------------------------------------------------------------------------
if [[ -n "$RESTORE_FILE" ]]; then
  if [[ ! -f "$RESTORE_FILE" ]]; then
    echo "ERROR: backup file not found: ${RESTORE_FILE}" >&2
    exit 2
  fi
  echo "=== Restoring custom:tenant_id from ${RESTORE_FILE} (pool ${USER_POOL_ID}) ==="
  restored=0
  while IFS=$'\t' read -r username old_value || [[ -n "$username" ]]; do
    [[ -z "$username" ]] && continue
    if [[ -z "$old_value" ]]; then
      echo "  - ${username}: clear custom:tenant_id (was unset)"
      clear_tenant "$username" || echo "    (warn: could not clear ${username})"
    else
      echo "  - ${username}: restore -> '${old_value}'"
      set_tenant "$username" "$old_value"
    fi
    restored=$((restored + 1))
  done < "$RESTORE_FILE"
  echo "=== Restore done. Users restored: ${restored} ==="
  exit 0
fi

# --------------------------------------------------------------------------
# Migrate mode
# --------------------------------------------------------------------------
echo "=== Migrating Cognito users: custom:tenant_id '${FROM_TENANT}' (or empty) -> '${TO_TENANT}' ==="
echo "    Pool: ${USER_POOL_ID}  Region: ${REGION}  Profile: ${PROFILE}  Dry-run: ${DRY_RUN}"

BACKUP_FILE=""
if [[ "$DRY_RUN" == "false" ]]; then
  mkdir -p "$BACKUP_DIR"
  BACKUP_FILE="${BACKUP_DIR}/tenant-migration-backup-$(date -u +%Y%m%dT%H%M%SZ).tsv"
  : > "$BACKUP_FILE"
  echo "    Backup: ${BACKUP_FILE}"
fi

next_token=""
migrated=0
while :; do
  if [[ -n "$next_token" ]]; then
    page=$(aws cognito-idp list-users --user-pool-id "$USER_POOL_ID" \
      --region "$REGION" --profile "$PROFILE" --pagination-token "$next_token" --no-cli-pager)
  else
    page=$(aws cognito-idp list-users --user-pool-id "$USER_POOL_ID" \
      --region "$REGION" --profile "$PROFILE" --no-cli-pager)
  fi

  while IFS=$'\t' read -r username tenant_id; do
    [[ -z "$username" ]] && continue
    if [[ "$tenant_id" == "$TO_TENANT" ]]; then
      continue # already migrated
    fi
    if [[ -n "$tenant_id" && "$tenant_id" != "$FROM_TENANT" ]]; then
      echo "  - skip ${username}: custom:tenant_id='${tenant_id}' (not '${FROM_TENANT}')"
      continue
    fi
    echo "  - update ${username}: '${tenant_id:-<empty>}' -> '${TO_TENANT}'"
    if [[ "$DRY_RUN" == "false" ]]; then
      # Record the prior value BEFORE changing it, so --restore is exact.
      printf '%s\t%s\n' "$username" "$tenant_id" >> "$BACKUP_FILE"
      set_tenant "$username" "$TO_TENANT"
    fi
    migrated=$((migrated + 1))
  done < <(echo "$page" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for u in data.get("Users", []):
    tid = ""
    for a in u.get("Attributes", []):
        if a["Name"] == "custom:tenant_id":
            tid = a.get("Value", "")
    print(u["Username"] + "\t" + tid)
')

  next_token=$(echo "$page" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("PaginationToken",""))')
  [[ -z "$next_token" ]] && break
done

echo "=== Done. Users updated: ${migrated} (dry-run=${DRY_RUN}) ==="
if [[ "$DRY_RUN" == "false" && "$migrated" -gt 0 ]]; then
  echo
  echo "Rollback this migration with:"
  echo "  PROFILE=${PROFILE} REGION=${REGION} USER_POOL_ID=${USER_POOL_ID} \\"
  echo "    ./scripts/migrate-default-tenant.sh --restore ${BACKUP_FILE}"
fi
echo
echo "NOTE: Applications and identity sources created under the '${FROM_TENANT}'"
echo "      tenant are NOT moved by this script. Re-register them under"
echo "      '${TO_TENANT}' via the console, or migrate the DynamoDB items"
echo "      (PK/SK and GSI keys) deliberately."
