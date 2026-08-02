FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm ci --omit=dev

COPY . .

EXPOSE 3001 3002 3003 3004 4000 4001 5173

CMD ["node", "zero-trust-proxy/server.js"]