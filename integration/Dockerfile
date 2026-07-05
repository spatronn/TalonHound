FROM node:22-alpine

WORKDIR /app

COPY integration/package*.json ./
RUN npm install --omit=dev

COPY integration/ ./
COPY backend/lib/ioc-suppression.js ./lib/ioc-suppression.js
COPY backend/lib/importOptimizationContext.js ./lib/importOptimizationContext.js
COPY backend/lib/iocExpiration.js ./lib/iocExpiration.js
COPY backend/lib/feedExpirationPolicy.js ./lib/feedExpirationPolicy.js
COPY backend/lib/iocFeedSourceEvidence.js ./lib/iocFeedSourceEvidence.js
COPY backend/lib/feedLifecycle.js ./lib/feedLifecycle.js
COPY backend/lib/iocActiveSources.js ./lib/iocActiveSources.js
COPY backend/lib/iocStatsCache.js ./lib/iocStatsCache.js
COPY backend/lib/clickhouse.js ./lib/clickhouse.js
COPY backend/lib/iocLookupSync.js ./lib/iocLookupSync.js
COPY backend/lib/ensure-db-password.js ./lib/ensure-db-password.js
COPY backend/lib/ensure-clickhouse-password.js ./lib/ensure-clickhouse-password.js
COPY backend/lib/auditIocContext.js ./lib/auditIocContext.js
COPY backend/lib/iocConfidence.js ./lib/iocConfidence.js
COPY backend/lib/auditConstants.js ./lib/auditConstants.js
COPY backend/lib/customThreatFeedUtils.js ./lib/customThreatFeedUtils.js
COPY backend/lib/customThreatFeedParser.js ./lib/customThreatFeedParser.js
COPY backend/lib/customThreatFeedAuth.js ./lib/customThreatFeedAuth.js
COPY backend/lib/customThreatFeedFetch.js ./lib/customThreatFeedFetch.js
COPY backend/lib/customThreatFeedSync.js ./lib/customThreatFeedSync.js
COPY backend/lib/customThreatFeedWorkerAudit.js ./lib/customThreatFeedWorkerAudit.js
COPY backend/lib/observable-normalization.js ./lib/observable-normalization.js
COPY backend/lib/feedFormatter.js ./lib/feedFormatter.js
COPY backend/lib/integrationQueueConfig.js ./lib/integrationQueueConfig.js
COPY backend/lib/integrationQueueRecovery.js ./lib/integrationQueueRecovery.js
COPY backend/lib/integrationQueueJobState.js ./lib/integrationQueueJobState.js
COPY backend/lib/integrationQueueBullmqReconciliation.js ./lib/integrationQueueBullmqReconciliation.js
COPY backend/lib/integrationQueueHealth.js ./lib/integrationQueueHealth.js
COPY backend/lib/integrationSchedule.js ./lib/integrationSchedule.js
COPY backend/lib/integrationFeedScheduleSync.js ./lib/integrationFeedScheduleSync.js
COPY backend/lib/iocClassificationMapping.js ./lib/iocClassificationMapping.js

CMD ["npm", "run", "worker"]
