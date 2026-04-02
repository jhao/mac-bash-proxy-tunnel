FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY README.md LICENSE ./

EXPOSE 7000

ENV PORT=7000

CMD ["sh", "-c", "node src/service.js --port ${PORT}"]
