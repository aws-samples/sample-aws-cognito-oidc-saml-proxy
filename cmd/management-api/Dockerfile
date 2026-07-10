FROM public.ecr.aws/lambda/provided:al2023-arm64
USER 993
COPY management-api /var/runtime/bootstrap
HEALTHCHECK NONE
CMD ["bootstrap"]
