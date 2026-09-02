# Multi-stage production build for MCP-Shield
FROM node:20-alpine AS builder

WORKDIR /app

RUN apk add --no-cache python3 make g++

COPY package*.json tsconfig*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production runtime stage
FROM node:20-alpine AS runner

WORKDIR /app

RUN apk add --no-cache tini python3 make g++

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/bin ./bin
COPY --from=builder /app/shield.config.default.yaml ./shield.config.default.yaml
COPY --from=builder /app/README.md ./README.md
COPY --from=builder /app/LICENSE ./LICENSE

RUN mkdir -p /app/.mcp-shield/logs /app/.mcp-shield/cow && \
    chown -R node:node /app

USER node

ENTRYPOINT ["/sbin/tini", "--", "node", "/app/dist/index.js"]
CMD ["wrap", "--"]
