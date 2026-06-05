# ==============================================================================
# Stage 1: Builder — Install Python dependencies and Trivy CLI
# ==============================================================================
FROM python:3.11-slim AS builder

# Install build tools for compiling Python C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy CLI
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Create virtual environment and install Python deps
WORKDIR /build
COPY app/requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ==============================================================================
# Stage 2: Runner — Minimal runtime image
# ==============================================================================
FROM python:3.11-slim AS runner

# Copy Trivy binary from builder
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy

# Copy Python virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set PATH to use the virtual environment
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy application code
COPY app/ .

# Create writable tmp dir for Trivy cache (container runs read-only root)
RUN mkdir -p /tmp/trivy-cache && chown -R appuser:appuser /tmp/trivy-cache /app
ENV TRIVY_CACHE_DIR=/tmp/trivy-cache

# Switch to non-root user
USER appuser

# Expose application port
EXPOSE ${PORT}

# Health check using Python (no curl needed in production image)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT}/health')" || exit 1

# Run with gunicorn in production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "main:app"]
