FROM node:22-alpine

ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG IMAGE_SOURCE=https://github.com/spatronn/TalonHound

LABEL org.opencontainers.image.title="TalonHound Integration"
LABEL org.opencontainers.image.description="TalonHound threat feed integration scheduler and worker"
LABEL org.opencontainers.image.source="${IMAGE_SOURCE}"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${BUILD_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"

ENV TALONHOUND_VERSION=${BUILD_VERSION}
ENV TALONHOUND_COMMIT=${BUILD_COMMIT}
ENV TALONHOUND_BUILD_DATE=${BUILD_DATE}

WORKDIR /app

COPY integration/package*.json ./
RUN npm install --omit=dev

COPY integration/ ./
COPY VERSION /VERSION
COPY backend/lib/ioc-suppression.js ./lib/ioc-suppression.js
COPY backend/lib/importOptimizationContext.js ./lib/importOptimizationContext.js
COPY backend/lib/iocExpiration.js ./lib/iocExpiration.js
COPY backend/lib/feedExpirationPolicy.js ./lib/feedExpirationPolicy.js
COPY backend/lib/iocFeedSourceEvidence.js ./lib/iocFeedSourceEvidence.js
COPY backend/lib/feedLifecycle.js ./lib/feedLifecycle.js
COPY backend/lib/iocActiveSources.js ./lib/iocActiveSources.js
COPY backend/lib/iocStatsCache.js ./lib/iocStatsCache.js
COPY backend/lib/ensure-db-password.js ./lib/ensure-db-password.js
COPY backend/lib/auditIocContext.js ./lib/auditIocContext.js
COPY backend/lib/iocConfidence.js ./lib/iocConfidence.js
COPY backend/lib/auditConstants.js ./lib/auditConstants.js
COPY backend/lib/customThreatFeedUtils.js ./lib/customThreatFeedUtils.js
COPY backend/lib/customThreatFeedParser.js ./lib/customThreatFeedParser.js
COPY backend/lib/customThreatFeedAuth.js ./lib/customThreatFeedAuth.js
COPY backend/lib/customThreatFeedSsrf.js ./lib/customThreatFeedSsrf.js
COPY backend/lib/customThreatFeedFetch.js ./lib/customThreatFeedFetch.js
COPY backend/lib/customThreatFeedSync.js ./lib/customThreatFeedSync.js
COPY backend/lib/customThreatFeedFingerprint.js ./lib/customThreatFeedFingerprint.js
COPY backend/lib/customThreatFeedWorkerAudit.js ./lib/customThreatFeedWorkerAudit.js
COPY backend/lib/observable-normalization.js ./lib/observable-normalization.js
COPY backend/lib/feedFormatter.js ./lib/feedFormatter.js
COPY backend/lib/integrationQueueConfig.js ./lib/integrationQueueConfig.js
COPY backend/lib/integrationQueueRecovery.js ./lib/integrationQueueRecovery.js
COPY backend/lib/integrationQueueJobState.js ./lib/integrationQueueJobState.js
COPY backend/lib/jobResultSnapshot.js ./lib/jobResultSnapshot.js
COPY backend/lib/feedLastRunResult.js ./lib/feedLastRunResult.js
COPY backend/lib/integrationRunCounters.js ./lib/integrationRunCounters.js
COPY backend/lib/feedHealth.js ./lib/feedHealth.js
COPY backend/lib/malwarebazaarCoverage.js /backend/lib/malwarebazaarCoverage.js
COPY backend/lib/malwarebazaarCoverage.js ./lib/malwarebazaarCoverage.js
COPY backend/lib/integrationQueueBullmqReconciliation.js ./lib/integrationQueueBullmqReconciliation.js
COPY backend/lib/integrationQueueHealth.js ./lib/integrationQueueHealth.js
COPY backend/lib/integrationSchedule.js ./lib/integrationSchedule.js
COPY backend/lib/integrationFeedScheduleSync.js ./lib/integrationFeedScheduleSync.js
COPY backend/lib/systemTime.js ./lib/systemTime.js
COPY backend/lib/appLogger.js ./lib/appLogger.js
COPY backend/lib/spamhausDropSync.js ./lib/spamhausDropSync.js
COPY backend/lib/spamhausDropScheduleSync.js ./lib/spamhausDropScheduleSync.js
COPY backend/lib/fileArtifactReconciliationScheduleSync.js ./lib/fileArtifactReconciliationScheduleSync.js
COPY backend/lib/iocClassificationMapping.js ./lib/iocClassificationMapping.js
COPY backend/lib/tagHelpers.js ./lib/tagHelpers.js
COPY backend/lib/tagCatalogService.js ./lib/tagCatalogService.js
COPY backend/lib/fileArtifacts /backend/lib/fileArtifacts

CMD ["npm", "run", "worker"]
