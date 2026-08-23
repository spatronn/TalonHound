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
RUN npm install --omit=dev
COPY backend/ ./
COPY VERSION /VERSION

EXPOSE 3000
CMD ["npm", "start"]
