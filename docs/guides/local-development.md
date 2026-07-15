# Local development

You can run the gateway and the demo apps entirely on your machine — no AWS account needed.
Local mode uses an in-memory store and a mock KMS signer.

```bash
make run-local      # Gateway on :8080 (in-memory store, mock KMS)
make test-sp        # SAML SP demo on :8081
make test-rp        # OIDC RP demo on :8082
make frontend-dev   # Admin console dev server on :3000
```

## Tests

```bash
make test               # unit tests
make test-integration   # integration-tagged tests (self-contained: in-memory + mock KMS/Cognito)
make test-e2e           # end-to-end-tagged tests (self-contained)
make lint               # golangci-lint + tflint
```

The integration and e2e suites are fully self-contained (in-memory stores plus a mock KMS
signer and a mock Cognito server over `httptest`), so they need no AWS credentials and run
in CI on every pull request.

See [Make commands](../reference/make-commands.md) for the full target list.
