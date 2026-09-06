# syntax=docker/dockerfile:1

# Frontend image. Next.js standalone output, so the runtime stage carries the
# server and its traced dependencies rather than the whole node_modules tree.
#
# This is the only service in docker-compose.offline.yml with a published
# port: the browser reaches it, and it reaches the backend over the internal
# network through its proxy route (LLD §11.2).

ARG NODE_VERSION=22

FROM node:${NODE_VERSION}-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:${NODE_VERSION}-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:${NODE_VERSION}-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# Next.js writes the standalone server plus only the files it traced as
# reachable. `static` and `public` are not traced and must be copied beside it.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public

USER node
EXPOSE 3000
CMD ["node", "server.js"]
