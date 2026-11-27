# Environment Configuration

Per-environment inputs for the three Terraform stacks. Only the `*.example` templates are
committed; the files you create from them are gitignored because they hold account IDs,
bucket names, domains, and email addresses.

| Template | Copy to | Used by |
|----------|---------|---------|
| `dev.tfvars.example` | `dev.tfvars` | All three stacks (`-var-file=../env/dev.tfvars`) |
| `registry.dev.backend.hcl.example` | `registry.dev.backend.hcl` | `infra/registry` state backend |
| `gateway.dev.backend.hcl.example` | `gateway.dev.backend.hcl` | `infra/gateway` state backend |
| `demo.dev.backend.hcl.example` | `demo.dev.backend.hcl` | `infra/demo` state backend |
| `dev.backend.hcl.example` | (reference only) | The keys every backend config must set |

For another environment, replace `dev` with `staging` or `prod` in the copied file names and
pass `ENV=<env>` to `make`. See
[docs/deployment/quickstart.md](../../docs/deployment/quickstart.md) for the full deployment
walkthrough.
