# ML Detector Application Dockerfile
FROM docker.io/library/python:3.11-slim

LABEL maintainer="eBPF AI Team"
LABEL description="ML-based threat detection for eBPF security"

# Install system dependencies for ML libraries
RUN apt-get update && apt-get install -y \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directory for ML models
RUN mkdir -p /tmp/models

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_ENV=production \
    PROMETHEUS_MULTIPROC_DIR=/tmp/prometheus

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash detector

# Create directories with proper ownership
RUN mkdir -p /data/models /tmp/models /tmp/prometheus && \
    chown -R detector:detector /app && \
    chown -R detector:detector /data && \
    chown -R detector:detector /tmp/models && \
    chown -R detector:detector /tmp/prometheus

# Set environment variable for model path (will be overridden by Kubernetes env)
ENV MODEL_PATH=/data/models

USER detector

# Expose application port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run application with Gunicorn (2 workers, 4 threads)
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app", "--workers", "2", "--threads", "4", "--timeout", "30"]
