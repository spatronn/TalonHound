FROM nginx:1.27-alpine

ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG IMAGE_SOURCE=https://github.com/spatronn/TalonHound

LABEL org.opencontainers.image.title="TalonHound Proxy"
LABEL org.opencontainers.image.description="TalonHound TLS reverse proxy"
LABEL org.opencontainers.image.source="${IMAGE_SOURCE}"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${BUILD_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"

COPY proxy/entrypoint.sh /entrypoint.sh
# Strip CR so Windows checkouts cannot break the Alpine shebang/exec form.
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
