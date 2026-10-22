# Build from the reference repository root. The npm lock fixes all JavaScript dependencies.
FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/agentlogin ./packages/agentlogin
COPY packages/rp ./packages/rp
COPY packages/rp-store-postgres ./packages/rp-store-postgres
COPY examples/rp-hono ./examples/rp-hono
RUN npm ci --ignore-scripts --no-audit --no-fund \
 && npx tsc -b packages/agentlogin packages/rp packages/rp-store-postgres \
 && npx tsc -p examples/rp-hono/tsconfig.build.json \
 && npm prune --omit=dev --ignore-scripts --no-audit --no-fund \
      --workspace=agentlogin-example-rp-hono --workspace=@agentlogin/rp \
      --workspace=@agentlogin/rp-store-postgres --workspace=agentlogin --include-workspace-root=false

FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS runtime
ENV NODE_ENV=production PORT=4000
WORKDIR /app
COPY --from=build --chown=node:node /app/package.json /app/package-lock.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/packages/agentlogin/package.json ./packages/agentlogin/package.json
COPY --from=build --chown=node:node /app/packages/agentlogin/bin ./packages/agentlogin/bin
COPY --from=build --chown=node:node /app/packages/agentlogin/dist ./packages/agentlogin/dist
COPY --from=build --chown=node:node /app/packages/rp/package.json ./packages/rp/package.json
COPY --from=build --chown=node:node /app/packages/rp/dist ./packages/rp/dist
COPY --from=build --chown=node:node /app/packages/rp-store-postgres/package.json ./packages/rp-store-postgres/package.json
COPY --from=build --chown=node:node /app/packages/rp-store-postgres/bin ./packages/rp-store-postgres/bin
COPY --from=build --chown=node:node /app/packages/rp-store-postgres/dist ./packages/rp-store-postgres/dist
COPY --from=build --chown=node:node /app/examples/rp-hono/package.json ./examples/rp-hono/package.json
COPY --from=build --chown=node:node /app/examples/rp-hono/dist ./examples/rp-hono/dist
USER node
EXPOSE 4000
CMD ["node", "examples/rp-hono/dist/server.js"]
