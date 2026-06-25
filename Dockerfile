# =====================================================================
# Farmsky — container image for AWS App Runner / ECS / any Docker host.
# Builds the Node server and runs it on port 8080.
# =====================================================================
FROM node:20-bookworm-slim AS build
WORKDIR /app
# build tools for better-sqlite3 (native module)
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build:node

FROM node:20-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080
# copy runtime artifacts + assets + migrations/seed (needed on first boot)
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist-node ./dist-node
COPY --from=build /app/public ./public
COPY --from=build /app/migrations ./migrations
COPY --from=build /app/seed.sql ./seed.sql
COPY --from=build /app/package.json ./package.json
EXPOSE 8080
CMD ["node", "dist-node/server.js"]
