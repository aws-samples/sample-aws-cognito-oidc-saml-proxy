#!/usr/bin/env bash
set -euo pipefail

SPEC_URL="${1:-http://localhost:8080/openapi.json}"
OUT_DIR="frontend/src/api"

mkdir -p "${OUT_DIR}"

echo "Fetching OpenAPI spec from ${SPEC_URL}..."
if ! curl -sf "${SPEC_URL}" -o "${OUT_DIR}/openapi.json"; then
  echo "Error: Failed to fetch OpenAPI spec from ${SPEC_URL}"
  echo "Make sure the proxy is running at the specified URL"
  exit 1
fi

echo "Generating TypeScript types..."
cd frontend && npx openapi-typescript "src/api/openapi.json" -o "src/api/schema.d.ts"

echo "Done. Types written to ${OUT_DIR}/schema.d.ts"
