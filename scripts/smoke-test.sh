#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:?Usage: $0 <base-url> [tenant]}"
TENANT="${2:-default}"   # the built-in tenant the gateway creates at startup

echo "=== Health ==="
curl -sf "${BASE_URL}/health" | jq .

echo "=== SAML Metadata ==="
curl -sf "${BASE_URL}/t/${TENANT}/saml/metadata" | head -3

echo "=== OIDC Discovery ==="
curl -sf "${BASE_URL}/t/${TENANT}/oidc/.well-known/openid-configuration" | jq '.issuer'

echo "=== OIDC JWKS ==="
curl -sf "${BASE_URL}/t/${TENANT}/oidc/keys" | jq '.keys | length'

echo "=== OpenAPI Spec ==="
curl -sf "${BASE_URL}/openapi.json" | jq '.info.title'

echo "=== Management API (expect 401 without token) ==="
# A local server with auth disabled returns 200; set EXPECT_API_STATUS=200 there.
EXPECTED="${EXPECT_API_STATUS:-401}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/v1/applications" || true)
echo "HTTP ${HTTP_CODE}"
if [[ "$HTTP_CODE" != "$EXPECTED" ]]; then
  echo "FAIL: expected ${EXPECTED} from the management API without a token, got ${HTTP_CODE}" >&2
  exit 1
fi

echo "=== All smoke tests passed ==="
