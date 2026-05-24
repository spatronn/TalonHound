FROM node:22-alpine

WORKDIR /app

COPY integration/package*.json ./
RUN npm install --omit=dev

COPY integration/ ./
COPY backend/lib/ioc-suppression.js ./lib/ioc-suppression.js

CMD ["npm", "run", "worker"]
