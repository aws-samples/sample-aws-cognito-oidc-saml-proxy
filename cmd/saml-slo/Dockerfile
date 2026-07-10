FROM public.ecr.aws/lambda/provided:al2023-arm64
USER 993
COPY saml-slo /var/runtime/bootstrap
HEALTHCHECK NONE
CMD ["bootstrap"]
