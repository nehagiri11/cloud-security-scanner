FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=3000
ENV CLOUD_SECURITY_DATA_DIR=/app/data

EXPOSE 3000

CMD ["node", "server.js"]
