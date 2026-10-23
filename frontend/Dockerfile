# ── Build stage ───────────────────────────────────────────────────────
FROM node:24.12.0-alpine AS builder

WORKDIR /build

# Copy only dependency files first for layer caching
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# Type-check and build the static bundle into /build/dist
COPY . .
RUN npm run build

# ── Runtime stage ────────────────────────────────────────────────────
# Unprivileged nginx: runs as a non-root user and listens on 8080
FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /build/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1

LABEL project="TREMOR" \
      description="TREMOR dashboard (React + Vite, served by nginx)"
