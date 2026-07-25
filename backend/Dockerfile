FROM node:20-alpine

RUN apk add --no-cache postgresql16-client tar

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .

EXPOSE 3000
CMD ["npm", "start"]
