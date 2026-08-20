# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install dependencies into a wheels directory to avoid compiling in final image
RUN pip wheel --no-cache-dir --wheel-dir /build/wheels -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Create dedicated non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -m -s /sbin/nologin appuser

WORKDIR /app

COPY --from=builder /build/wheels /wheels
COPY --from=builder /build/requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt && rm -rf /wheels

# Copy application source code read-only, ensuring correct permissions
COPY --chown=root:root app/ app/
COPY --chown=root:root scripts/ scripts/

# Create a writable directory for local databases / runtime state if needed
RUN mkdir -p /app/data && chown -R appuser:appgroup /app/data

# Declare mount point for writable filesystem
VOLUME /app/data

# Ensure static dashboard files are readable
RUN chmod -R 755 /app/app/static

# Set environment defaults
ENV APP_ENV=production \
    PORT=8000 \
    DATABASE_URL="sqlite+aiosqlite:////app/data/agent_waf.db" \
    PYTHONUNBUFFERED=1

# Expose default port
EXPOSE 8000

# Switch to non-root application user
USER appuser

# Healthcheck configuration using python script to verify liveness
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request, os, sys; \
port = os.getenv('PORT', '8000'); \
url = f'http://localhost:{port}/health'; \
res = urllib.request.urlopen(url); \
sys.exit(0) if res.status == 200 else sys.exit(1)"

# Uvicorn run command
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --workers 1"]
