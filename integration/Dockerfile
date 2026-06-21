FROM node:22-alpine

WORKDIR /app

COPY integration/package*.json ./
RUN npm install --omit=dev

COPY integration/ ./
COPY backend/lib/ioc-suppression.js ./lib/ioc-suppression.js
COPY backend/lib/iocExpiration.js ./lib/iocExpiration.js
COPY backend/lib/feedLifecycle.js ./lib/feedLifecycle.js
COPY backend/lib/auditIocContext.js ./lib/auditIocContext.js
COPY backend/lib/iocConfidence.js ./lib/iocConfidence.js
COPY backend/lib/integrationQueueConfig.js ./lib/integrationQueueConfig.js
COPY backend/lib/integrationQueueRecovery.js ./lib/integrationQueueRecovery.js
COPY backend/lib/integrationQueueJobState.js ./lib/integrationQueueJobState.js
COPY backend/lib/integrationQueueBullmqReconciliation.js ./lib/integrationQueueBullmqReconciliation.js
COPY backend/lib/integrationQueueHealth.js ./lib/integrationQueueHealth.js
COPY backend/lib/integrationSchedule.js ./lib/integrationSchedule.js
COPY backend/lib/integrationFeedScheduleSync.js ./lib/integrationFeedScheduleSync.js

CMD ["npm", "run", "worker"]
