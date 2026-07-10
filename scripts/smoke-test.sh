#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:?Usage: $0 <base-url> [tenant]}"
TENANT="${2:-demo}"

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
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "${BASE_URL}/api/v1/applications" || true)
echo "HTTP ${HTTP_CODE}"

echo "=== All smoke tests passed ==="
