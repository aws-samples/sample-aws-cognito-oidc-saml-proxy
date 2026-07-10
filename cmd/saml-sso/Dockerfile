FROM public.ecr.aws/lambda/provided:al2023-arm64
# Lambda's provided runtime runs as the lambda user (uid 993); explicitly
# declare it so Checkov CKV_DOCKER_3 (non-root) is satisfied.
USER 993
COPY saml-sso /var/runtime/bootstrap
# Lambda processes are health-checked externally by the runtime; this
# instruction satisfies Checkov CKV_DOCKER_2 for container image scanners.
HEALTHCHECK NONE
CMD ["bootstrap"]
