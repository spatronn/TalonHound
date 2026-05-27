FROM node:22-alpine

WORKDIR /app

COPY integration/package*.json ./
RUN npm install --omit=dev

COPY integration/ ./
COPY backend/lib/ioc-suppression.js ./lib/ioc-suppression.js
COPY backend/lib/iocExpiration.js ./lib/iocExpiration.js

CMD ["npm", "run", "worker"]
