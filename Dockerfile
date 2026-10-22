# ------------------------------------------------------------------ #
#  Multi-stage Dockerfile                                              #
#                                                                      #
#  Stage 1 (builder): install dependencies                            #
#  Stage 2 (runtime): copy only what's needed to run the app         #
#                                                                      #
#  Multi-stage builds keep the final image small and clean —          #
#  build tools, pip cache, and temporary files never make it          #
#  into the image you deploy.                                          #
# ------------------------------------------------------------------ #

# ---- Stage 1: Builder -------------------------------------------- #
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /build

# Install system dependencies needed to compile some Python packages
# (psycopg2-binary bundles its own libpq so we only need build-essential
# for anything that compiles C extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first — Docker caches this layer.
# If requirements.txt hasn't changed, pip install is skipped on rebuild.
COPY requirements.txt .

# Install all Python dependencies into a local directory
RUN pip install --upgrade pip && \
    pip install --prefix=/install --no-cache-dir -r requirements.txt


# ---- Stage 2: Runtime -------------------------------------------- #
FROM python:3.11-slim AS runtime

# Security: run as non-root user
# Running as root inside a container is a security risk —
# if the app is compromised, the attacker gets root in the container.
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application code
COPY app/ ./app/

# Create uploads directory and set permissions
RUN mkdir -p /app/uploads && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check — Docker will ping this to know if the container
# is healthy. Render and Railway also use it.
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

# Start the application
# --host 0.0.0.0  → listen on all interfaces (required inside Docker)
# --workers 2     → two worker processes for concurrent requests
# --timeout-keep-alive 30 → close idle connections after 30s
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--timeout-keep-alive", "30", \
     "--access-log"]
