FROM node:22-alpine

WORKDIR /app

COPY integration/package*.json ./
RUN npm install --omit=dev

COPY integration/ ./
COPY backend/lib/ioc-suppression.js ./lib/ioc-suppression.js
COPY backend/lib/iocExpiration.js ./lib/iocExpiration.js
COPY backend/lib/iocConfidence.js ./lib/iocConfidence.js
COPY backend/lib/integrationQueueConfig.js ./lib/integrationQueueConfig.js
COPY backend/lib/integrationQueueRecovery.js ./lib/integrationQueueRecovery.js
COPY backend/lib/integrationQueueJobState.js ./lib/integrationQueueJobState.js

CMD ["npm", "run", "worker"]
