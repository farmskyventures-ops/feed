FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=optional

COPY . .
RUN npm run build:node

ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "dist-node/server.js"]
