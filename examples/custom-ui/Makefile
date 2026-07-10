# Build + deploy the standalone Cognito custom-UI demo.
#
# Security model (mirrors the Federation Gateway console): the SPA is served from
# a PRIVATE S3 bucket via CloudFront with Origin Access Control, guarded by a WAF
# IP allowlist. There is no Lambda Function URL and no public principal.
#
# Configure your pool/client + your IP in infra/terraform.tfvars (see the example).

AWS_REGION  ?= us-east-1
NAME_PREFIX ?= cognito-custom-ui-demo

.PHONY: help dev frontend-build tf-init tf-apply sync invalidate deploy destroy clean

help:
	@echo "Targets:"
	@echo "  dev            Run the SPA locally (npm run dev) — needs frontend/.env.local"
	@echo "  frontend-build Build the SPA (frontend/dist)"
	@echo "  deploy         terraform apply -> sync assets to S3 -> invalidate CloudFront"
	@echo "  destroy        empty the SPA bucket -> terraform destroy"

dev:
	cd frontend && npm install && npm run dev

frontend-build:
	cd frontend && npm install && npm run build

tf-init:
	cd infra && terraform init -input=false

tf-apply: tf-init
	cd infra && terraform apply -input=false -auto-approve

# Sync built assets to the private bucket. Excludes config.json (managed by
# Terraform) so --delete does not remove it.
sync:
	cd infra && \
	  BUCKET=$$(terraform output -raw bucket_name) && \
	  aws s3 sync ../frontend/dist/ s3://$$BUCKET --delete --exclude config.json --region $(AWS_REGION)

invalidate:
	cd infra && \
	  DIST=$$(terraform output -raw cloudfront_distribution_id) && \
	  aws cloudfront create-invalidation --distribution-id $$DIST --paths "/*" --region $(AWS_REGION) --no-cli-pager >/dev/null
	@echo "Deployed. App URL (reachable only from allowed_cidrs):"
	@cd infra && terraform output -raw app_url

deploy: frontend-build tf-apply sync invalidate

# Empty the private SPA bucket first — it is not force_destroy, so Terraform
# cannot delete it while the synced assets remain. The bucket name comes from
# the Terraform output; the step is a no-op if state/bucket is already gone.
destroy:
	cd infra && \
	  BUCKET=$$(terraform output -raw bucket_name 2>/dev/null) && \
	  if [ -n "$$BUCKET" ]; then \
	    echo "Emptying s3://$$BUCKET before destroy"; \
	    aws s3 rm s3://$$BUCKET --recursive --region $(AWS_REGION) >/dev/null 2>&1 || true; \
	  fi; \
	  terraform destroy -input=false -auto-approve

clean:
	rm -rf frontend/dist
