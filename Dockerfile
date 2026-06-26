# =====================================================================
# Farmsky — container image for AWS App Runner / ECS / any Docker host.
# Builds the Node server and runs it on port 8080.
# Requires a PostgreSQL database; configure via DATABASE_URL (or PG* env).
# =====================================================================
FROM node:20-bookworm-slim AS build
WORKDIR /app
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
COPY --from=build /app/migrations-pg ./migrations-pg
COPY --from=build /app/seed-pg.sql ./seed-pg.sql
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/package.json ./package.json
EXPOSE 8080
# DATABASE_URL (or PGHOST/PGUSER/PGPASSWORD/PGDATABASE) must be provided at runtime.
CMD ["node", "dist-node/server.js"]
