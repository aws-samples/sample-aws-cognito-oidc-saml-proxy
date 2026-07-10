.PHONY: build test test-integration test-e2e lint clean docker-build fmt vet frontend-install frontend-build frontend-deploy frontend-dev frontend-lint generate-types build-all lint-all build-all-lambdas docker-build-all security-scan security-scan-strict registry-init registry-apply push-function-images push-demo-images gateway-init gateway-apply demo-init demo-apply deploy-dev registry-destroy gateway-destroy demo-destroy destroy-dev tf-init tf-plan tf-validate

BINARY_NAME := proxy
BUILD_DIR := bin
GO_FLAGS := -trimpath -ldflags="-s -w"
DOCKER_IMAGE := saml-proxy
AWS_PROFILE := default
AWS_REGION := us-east-1
FUNCTIONS := saml-sso saml-slo saml-metadata oidc-authorize oidc-token oidc-discovery management-api health
# Deploy environment. Selects both the tfvars and the per-stack S3 backend
# config file (infra/env/<stack>.$(ENV).backend.hcl). Override e.g. `make
# deploy-dev ENV=staging`.
ENV ?= dev
# Terraform var-file, relative to each stack dir under infra/ (all three stacks
# read the same env inputs via their symlinked variables.tf).
TFVARS := ../env/$(ENV).tfvars

# Each stack declares an empty `backend "s3" {}`, so `terraform init` must be
# given the bucket/key at init time via -backend-config. The config lives at
# infra/env/<stack>.$(ENV).backend.hcl (gitignored, copied from the .example).
# When that file is present we pass it; when it is absent (offline `terraform
# validate`/`test`, or a local-state setup) init runs without it and Terraform
# uses local state. $(wildcard) is evaluated from the repo root (the Makefile
# dir); the path handed to terraform is relative to the -chdir stack dir.
# Usage: $(call tf_backend_config,<stack>)
tf_backend_config = $(if $(wildcard infra/env/$(1).$(ENV).backend.hcl),-backend-config=../env/$(1).$(ENV).backend.hcl,)

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GO_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/proxy/

build-local:
	go build $(GO_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/proxy/

frontend-install:
	cd frontend && npm ci

# Cognito config is read from the GATEWAY stack outputs. The infra was split into
# registry/gateway/demo stacks, so these outputs now live in infra/gateway (not the
# old single-state infra/). VITE_COGNITO_DOMAIN must be a bare host — Amplify's
# oauth.domain rejects a scheme — so strip the https:// the output carries.
frontend-build: frontend-install
	cd frontend && \
		VITE_COGNITO_USER_POOL_ID=$$(AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=../infra/gateway output -raw cognito_user_pool_id 2>/dev/null) \
		VITE_COGNITO_CLIENT_ID=$$(AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=../infra/gateway output -raw cognito_spa_client_id 2>/dev/null) \
		VITE_COGNITO_DOMAIN=$$(AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=../infra/gateway output -raw cognito_domain 2>/dev/null | sed 's|https://||') \
		npm run build

frontend-dev:
	cd frontend && npm run dev

# Build the SPA, sync it to the frontend S3 bucket, and invalidate CloudFront.
# Bucket name and distribution id are read from Terraform outputs, so this works
# across environments without hardcoding. Requires an applied infra state.
frontend-deploy: frontend-build
	@BUCKET=$$(AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/gateway output -raw frontend_bucket_name 2>/dev/null); \
	DIST=$$(AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/gateway output -raw cloudfront_distribution_id 2>/dev/null); \
	if [ -z "$$BUCKET" ] || [ -z "$$DIST" ]; then \
		echo "ERROR: could not read frontend_bucket_name / cloudfront_distribution_id from Terraform outputs."; \
		echo "       Run 'make tf-init' and apply infra first, or check AWS_PROFILE=$(AWS_PROFILE)."; \
		exit 1; \
	fi; \
	echo "==> Syncing frontend/dist/ -> s3://$$BUCKET"; \
	aws s3 sync frontend/dist/ s3://$$BUCKET --delete --profile $(AWS_PROFILE) --region $(AWS_REGION); \
	echo "==> Invalidating CloudFront distribution $$DIST"; \
	aws cloudfront create-invalidation --distribution-id $$DIST --paths '/*' \
		--profile $(AWS_PROFILE) --no-cli-pager \
		--query 'Invalidation.{Id:Id,Status:Status}' --output table; \
	echo "==> Frontend deployed."

frontend-lint:
	cd frontend && npx tsc --noEmit

generate-types:
	@echo "Generating TypeScript types from OpenAPI spec..."
	cd frontend && npx openapi-typescript http://localhost:8080/openapi.json -o src/api/schema.d.ts

build-all: build frontend-build

lint-all: lint frontend-lint

test:
	go test -race -count=1 ./internal/...

test-integration:
	go test -race -count=1 -tags=integration ./internal/...

test-e2e:
	go test -race -count=1 -tags=e2e ./internal/...

test-cover:
	go test -race -coverprofile=coverage.out ./internal/...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...
	cd infra && tflint --recursive

fmt:
	go fmt ./...
	goimports -w .

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html

# Run the local security scanner suite (mirrors the Probe/Holmes CI jobs).
# Gates on ERROR/HIGH+ findings; results written to scan-results/ (gitignored).
security-scan:
	./scripts/security-scan.sh

# Stricter gate: also fail on WARNING/MEDIUM findings.
security-scan-strict:
	SEVERITY_GATE=warning ./scripts/security-scan.sh

docker-build:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GO_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/proxy/
	docker build --platform linux/arm64 -t $(DOCKER_IMAGE):latest .

build-all-lambdas:
	@for fn in $(FUNCTIONS); do \
		echo "Building $$fn..."; \
		CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GO_FLAGS) -o $(BUILD_DIR)/$$fn ./cmd/$$fn/; \
	done

docker-build-all: build-all-lambdas
	@for fn in $(FUNCTIONS); do \
		echo "Building Docker image for $$fn..."; \
		docker build --platform linux/arm64 -t $$fn:latest -f cmd/$$fn/Dockerfile $(BUILD_DIR)/; \
	done

# ---------------------------------------------------------------------------
# Split-stack deploy (registry -> images -> gateway -> demo -> frontend)
#
# The infra was split into three independently-stated stacks under infra/:
#   registry/ (ECR repos)  gateway/ (the gateway + Cognito + frontend bucket/CDN)
#   demo/     (demo SAML SP + OIDC RP)
# The gateway/demo stacks read the registry stack's ECR URLs via remote_state,
# so the order is fixed: registry apply -> push images -> gateway apply -> demo
# apply. Image repo names and the frontend bucket are read from Terraform
# outputs (never hardcoded), so these targets track var.name_suffix correctly.
# ---------------------------------------------------------------------------

registry-init:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/registry init $(call tf_backend_config,registry)

registry-apply:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/registry apply -var-file=$(TFVARS) -auto-approve

# Build the 8 arm64 Lambda binaries and push each to ITS registry-stack ECR repo.
# Repo URLs come from the registry output map, so the correct name_suffix is used
# automatically. Requires the registry stack to be applied first.
# Build all Lambda images, push each with the current git SHA as tag (ECR
# repos are IMMUTABLE so 'latest' cannot be overwritten once set), capture
# the immutable digest returned by ECR, and write every digest into dev.tfvars
# under image_digests so gateway-apply can deploy by digest (MF-12).
push-function-images: build-all-lambdas
	@URLS=$$(AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/registry output -json ecr_repository_urls 2>/dev/null); \
	if [ -z "$$URLS" ] || [ "$$URLS" = "null" ]; then \
		echo "ERROR: could not read ecr_repository_urls from the registry stack. Run 'make registry-init registry-apply' first."; exit 1; \
	fi; \
	REG=$$(echo "$$URLS" | jq -r 'to_entries[0].value | split("/")[0]'); \
	TAG=$$(git rev-parse --short HEAD 2>/dev/null || echo "dev"); \
	echo "==> ECR login to $$REG (tag: $$TAG)"; \
	AWS_PROFILE=$(AWS_PROFILE) aws ecr get-login-password --region $(AWS_REGION) | docker login --username AWS --password-stdin $$REG; \
	DIGESTS_JSON="{"; FIRST=1; \
	for fn in $(FUNCTIONS); do \
		REPO=$$(echo "$$URLS" | jq -r --arg k "$$fn" '.[$$k]'); \
		if [ "$$REPO" = "null" ] || [ -z "$$REPO" ]; then echo "ERROR: no ECR repo for $$fn in registry output"; exit 1; fi; \
		ref="$$REPO:$$TAG"; \
		echo "==> $$fn: build + push $$ref"; \
		DOCKER_BUILDKIT=0 docker build --platform linux/arm64 -t "$$ref" -f cmd/$$fn/Dockerfile $(BUILD_DIR)/; \
		docker push "$$ref"; \
		DIGEST=$$(AWS_PROFILE=$(AWS_PROFILE) aws ecr describe-images \
			--region $(AWS_REGION) \
			--repository-name "$$(echo $$REPO | cut -d/ -f2-)" \
			--image-ids imageTag=$$TAG \
			--query 'imageDetails[0].imageDigest' \
			--output text 2>/dev/null); \
		echo "    digest: $$DIGEST"; \
		if [ "$$FIRST" = "1" ]; then FIRST=0; else DIGESTS_JSON="$$DIGESTS_JSON,"; fi; \
		DIGESTS_JSON="$$DIGESTS_JSON \"$$fn\": \"$$DIGEST\""; \
	done; \
	DIGESTS_JSON="$$DIGESTS_JSON }"; \
	echo "==> Writing image_digests to $(TFVARS)"; \
	TF_BLOCK=$$(echo "$$DIGESTS_JSON" | jq -r 'to_entries | map("  \"" + .key + "\" = \"" + .value + "\"") | "image_digests = {\n" + join("\n") + "\n}"'); \
	TFVARS_PATH="infra/gateway/$(TFVARS)"; \
	if command grep -q "^image_digests" "$$TFVARS_PATH" 2>/dev/null; then \
		awk -v block="$$TF_BLOCK" 'BEGIN{skip=0} /^image_digests[[:space:]]*=/{skip=1} skip && /\}/{skip=0; print block; next} !skip{print}' "$$TFVARS_PATH" > "$$TFVARS_PATH.tmp" && mv "$$TFVARS_PATH.tmp" "$$TFVARS_PATH"; \
	else \
		printf '\n%s\n' "$$TF_BLOCK" >> "$$TFVARS_PATH"; \
	fi; \
	echo "==> function images pushed. image_digests written to $(TFVARS)."

# Build + push the two demo images (SAML SP, OIDC RP) to their registry-stack ECR repos.
push-demo-images:
	@SAML=$$(AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/registry output -raw ecr_demo_saml_url 2>/dev/null); \
	OIDC=$$(AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/registry output -raw ecr_demo_oidc_url 2>/dev/null); \
	if [ -z "$$SAML" ] || [ -z "$$OIDC" ]; then \
		echo "ERROR: could not read demo ECR URLs from the registry stack. Run 'make registry-init registry-apply' first."; exit 1; \
	fi; \
	REG=$$(echo "$$SAML" | cut -d/ -f1); \
	TAG=$$(git rev-parse --short HEAD 2>/dev/null || echo "dev"); \
	echo "==> ECR login to $$REG (tag: $$TAG)"; \
	AWS_PROFILE=$(AWS_PROFILE) aws ecr get-login-password --region $(AWS_REGION) | docker login --username AWS --password-stdin $$REG; \
	echo "==> test-sp: build binary + image $$SAML:$$TAG"; \
	( cd scripts/test-sp && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GO_FLAGS) -o test-sp . ); \
	DOCKER_BUILDKIT=0 docker build --platform linux/arm64 -t "$$SAML:$$TAG" -f scripts/test-sp/Dockerfile scripts/test-sp; \
	docker push "$$SAML:$$TAG"; \
	echo "==> test-rp: build binary + image $$OIDC:$$TAG"; \
	( cd scripts/test-rp && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GO_FLAGS) -o test-rp . ); \
	DOCKER_BUILDKIT=0 docker build --platform linux/arm64 -t "$$OIDC:$$TAG" -f scripts/test-rp/Dockerfile scripts/test-rp; \
	docker push "$$OIDC:$$TAG"
	@echo "==> demo images pushed."

gateway-init:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/gateway init $(call tf_backend_config,gateway)

gateway-apply:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/gateway apply -var-file=$(TFVARS) -auto-approve

demo-init:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/demo init $(call tf_backend_config,demo)

demo-apply:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/demo apply -var-file=$(TFVARS) -auto-approve

# Full ordered deploy. Sub-invokes each step via $(MAKE) so the registry ->
# images -> gateway -> demo -> frontend ordering is strict regardless of -j.
# NOTE: post-install (admin user, tenant, register the SAML + OIDC apps) is a
# separate scripted step, not part of this target.
deploy-dev:
	$(MAKE) registry-init AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	$(MAKE) registry-apply AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	$(MAKE) push-function-images AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	$(MAKE) push-demo-images AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	$(MAKE) gateway-init AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	$(MAKE) gateway-apply AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	$(MAKE) demo-init AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	$(MAKE) demo-apply AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	$(MAKE) frontend-deploy AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	@echo "==> deploy-dev complete. Next: post-install (admin user, tenant, register SAML+OIDC apps), then E2E."

# ---------------------------------------------------------------------------
# Teardown (reverse of deploy: demo -> gateway -> registry)
#
# Destroy order is the strict reverse of the apply order. The demo and gateway
# stacks read the registry stack via remote_state, so the registry stack MUST be
# destroyed LAST. Each target re-runs `init` so teardown works from a clean shell
# (e.g. a fresh clone with only the S3 backend configured).
#
# Two teardown snags this handles automatically:
#   - The gateway's frontend + IaC-template S3 buckets are NOT force_destroy, so
#     a non-empty bucket blocks `terraform destroy`. gateway-destroy empties both
#     (names read from Terraform outputs) before destroying.
#   - ECR repos use repository_force_delete in non-prod (var.environment != prod),
#     so pushed images are removed automatically — no manual purge needed.
#
# CloudFront can be slow to disassociate; if a WAF web ACL deletion fails because
# CloudFront is still tearing down, re-run the same target a few minutes later.
# ---------------------------------------------------------------------------

demo-destroy:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/demo init $(call tf_backend_config,demo)
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/demo destroy -var-file=$(TFVARS) -auto-approve

gateway-destroy:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/gateway init $(call tf_backend_config,gateway)
	@for out in frontend_bucket_name iac_templates_bucket_name; do \
		B=$$(AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/gateway output -raw $$out 2>/dev/null); \
		if [ -n "$$B" ]; then \
			echo "==> Emptying s3://$$B before destroy"; \
			aws s3 rm s3://$$B --recursive --profile $(AWS_PROFILE) --region $(AWS_REGION) >/dev/null 2>&1 || true; \
		fi; \
	done
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/gateway destroy -var-file=$(TFVARS) -auto-approve

registry-destroy:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/registry init $(call tf_backend_config,registry)
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/registry destroy -var-file=$(TFVARS) -auto-approve

# Full ordered teardown — the mirror image of deploy-dev. Sub-invokes each step
# via $(MAKE) so the demo -> gateway -> registry ordering holds regardless of -j.
destroy-dev:
	$(MAKE) demo-destroy AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	$(MAKE) gateway-destroy AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	$(MAKE) registry-destroy AWS_PROFILE=$(AWS_PROFILE) ENV=$(ENV)
	@echo "==> destroy-dev complete. All three stacks torn down."

# Per-stack plan/validate helpers. STACK defaults to gateway; override e.g.
# `make tf-plan STACK=demo`.
STACK ?= gateway

tf-init:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/$(STACK) init $(call tf_backend_config,$(STACK))

tf-plan:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/$(STACK) plan -var-file=$(TFVARS)

tf-validate:
	AWS_PROFILE=$(AWS_PROFILE) terraform -chdir=infra/$(STACK) validate

run-local:
	PROXY_LOG_LEVEL=debug \
	PROXY_PORT=8080 \
	PROXY_ENVIRONMENT=local \
	PROXY_BASE_URL=http://localhost:8080 \
	PROXY_ENTITY_ID=http://localhost:8080 \
	go run ./cmd/proxy/

test-sp:
	cd scripts/test-sp && go run main.go

test-rp:
	cd scripts/test-rp && go run main.go
