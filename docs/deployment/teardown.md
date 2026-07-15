# Teardown

Tear everything down with the centralized target — the mirror of `make deploy-dev`, which
destroys the stacks in reverse dependency order (demo → gateway → registry):

```bash
make destroy-dev ENV=dev AWS_PROFILE=<profile>
```

Or destroy a single stack at a time (same reverse order):

```bash
make demo-destroy    ENV=dev AWS_PROFILE=<profile>
make gateway-destroy ENV=dev AWS_PROFILE=<profile>   # empties the frontend + IaC buckets first
make registry-destroy ENV=dev AWS_PROFILE=<profile>  # must be last: other stacks read it via remote_state
```

## Notes

- `make gateway-destroy` empties the frontend and IaC-template S3 buckets before destroying,
  since neither sets `force_destroy`.
- ECR repositories use `repository_force_delete` in non-prod, so images are removed
  automatically.
- If a WAF web ACL is slow to delete because CloudFront is still disassociating, re-run the
  same target a few minutes later.
- The Terraform **state bucket** is separate from the stacks and is not deleted by these
  targets — so you can redeploy without re-bootstrapping the backend.
