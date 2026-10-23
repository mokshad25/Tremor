# ── Build stage ───────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Copy only dependency files first for layer caching
COPY pyproject.toml ./

# Install build deps (includes dev for potential build scripts)
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

# ── Runtime stage ────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: non-root user (UID 1001 as per spec)
RUN groupadd --gid 1001 tremor \
    && useradd --uid 1001 --gid tremor --shell /bin/false --create-home tremor

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY app/ ./app/
COPY simulator/ ./simulator/
COPY eval/ ./eval/
COPY pyproject.toml ./

# Create dirs for data, logs, and sample input
RUN mkdir -p /app/sample /app/data /app/logs \
    && chown -R tremor:tremor /app

# Switch to non-root
USER tremor

EXPOSE 8000

# Health check against the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Labels for container metadata
LABEL maintainer="VaradSinghal" \
      project="TREMOR" \
      description="Trend-aware Real-time Event Monitoring & Outlier Response"

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
