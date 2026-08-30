FROM node:20-alpine

ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG IMAGE_SOURCE=https://github.com/spatronn/TalonHound

LABEL org.opencontainers.image.title="TalonHound Backend"
LABEL org.opencontainers.image.description="TalonHound backend API and worker runtime"
LABEL org.opencontainers.image.source="${IMAGE_SOURCE}"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${BUILD_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"

ENV TALONHOUND_VERSION=${BUILD_VERSION}
ENV TALONHOUND_COMMIT=${BUILD_COMMIT}
ENV TALONHOUND_BUILD_DATE=${BUILD_DATE}

RUN apk add --no-cache postgresql16-client tar

WORKDIR /app
COPY backend/package*.json ./
# Build toolchain is needed to compile native deps (bcrypt) from source on architectures
# without a published prebuilt binary for node:20-alpine/musl (e.g. arm64). Installed as a
# virtual package and removed in the same layer so the runtime image stays slim.
RUN apk add --no-cache --virtual .build-deps python3 make g++ \
 && npm install --omit=dev \
 && apk del .build-deps
COPY backend/ ./
COPY VERSION /VERSION

EXPOSE 3000
CMD ["npm", "start"]
