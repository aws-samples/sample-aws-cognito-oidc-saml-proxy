FROM public.ecr.aws/lambda/provided:al2023-arm64
USER 993
COPY bin/proxy /var/runtime/bootstrap
HEALTHCHECK NONE
CMD ["bootstrap"]
