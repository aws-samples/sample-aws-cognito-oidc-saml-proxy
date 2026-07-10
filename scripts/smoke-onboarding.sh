#!/usr/bin/env bash
# scripts/smoke-onboarding.sh
# Walks the 6-step onboarding wizard via curl. Exits 0 if every step succeeds.
# Usage: ./scripts/smoke-onboarding.sh [BASE_URL]
# Defaults to http://localhost:8080 (run the management-api locally).

set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"
SLUG="acme-smoke-$(date +%s)"
SCRIPT_NAME="$(basename "$0")"

echo "[$SCRIPT_NAME] using BASE_URL=$BASE_URL slug=$SLUG"

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo; echo "--- $* ---"; }

# Step 1 — create
step "step 1: create tenant"
curl -fsS -X POST "$BASE_URL/api/v1/onboarding" \
	-H 'Content-Type: application/json' \
	-d "{\"slug\":\"$SLUG\",\"displayName\":\"Acme Smoke\"}" || fail "create"

# Step 2 — capabilities
step "step 2: set capabilities"
curl -fsS -X PUT "$BASE_URL/api/v1/onboarding/$SLUG/capabilities" \
	-H 'Content-Type: application/json' \
	-d '{"packs":["core","user_directory"]}' || fail "capabilities"

# Step 3 — IaC (CFN)
step "step 3: generate IaC"
IAC=$(curl -fsS -X POST "$BASE_URL/api/v1/onboarding/$SLUG/iac" \
	-H 'Content-Type: application/json' \
	-d '{"format":"cfn"}')
echo "$IAC"
EXT_ID=$(echo "$IAC" | grep -oE '"externalId":"[^"]+"' | cut -d'"' -f4)
[ -n "$EXT_ID" ] || fail "no ExternalID returned"
echo "ExternalID: $EXT_ID"

# Plan B2: downloadUrl and cloudformationQuickCreateUrl should be present
# when management-api is configured with IaCTemplatesBucket (production config).
# In B1-compat local dev (no bucket configured) these are empty — skip.
DL=$(echo "$IAC" | grep -oE '"downloadUrl":"[^"]+"' | cut -d'"' -f4 || true)
if [ -n "$DL" ]; then
	echo "Download URL: $DL"
	curl -sI "$DL" >/dev/null || fail "downloadUrl not publicly fetchable"
fi
QC=$(echo "$IAC" | grep -oE '"cloudformationQuickCreateUrl":"[^"]+"' | cut -d'"' -f4 || true)
[ -n "$QC" ] && echo "QuickCreate: $QC"

# Step 4 — identity
step "step 4: register identity"
curl -fsS -X POST "$BASE_URL/api/v1/onboarding/$SLUG/identity" \
	-H 'Content-Type: application/json' \
	-d '{
		"roleArn":"arn:aws:iam::123456789012:role/identity-gateway-'"$SLUG"'",
		"poolId":"eu-north-1_smoke999",
		"clientId":"smoke-client-abc",
		"secretArn":"arn:aws:secretsmanager:eu-north-1:123456789012:secret:smoke-AB",
		"region":"eu-north-1"
	}' || fail "identity"

# Step 5 — probe (stub)
step "step 5: probe (stubbed)"
curl -fsS -X POST "$BASE_URL/api/v1/onboarding/$SLUG/probe" \
	-H 'Content-Type: application/json' || fail "probe"

# Step 6 — complete
step "step 6: complete"
curl -fsS -X POST "$BASE_URL/api/v1/onboarding/$SLUG/complete" \
	-H 'Content-Type: application/json' || fail "complete"

# Resume should return 404 now
step "post-completion: GetState returns 404"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/api/v1/onboarding/$SLUG")
[ "$STATUS" = "404" ] || fail "expected 404 after completion, got $STATUS"

echo
echo "[$SCRIPT_NAME] SUCCESS — tenant $SLUG completed onboarding"
