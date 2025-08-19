# eBPF Monitor Application Dockerfile
FROM docker.io/library/golang:1.21-alpine AS builder

LABEL maintainer="eBPF AI Team"
LABEL description="eBPF-based network monitoring and metrics collection"

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev linux-headers

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o ebpf-monitor ./cmd/monitor

# Final stage
FROM docker.io/library/alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates curl

# Create non-root user
RUN adduser -D -s /bin/sh monitor

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/ebpf-monitor .
COPY --from=builder /app/config/ ./config/

# Change ownership
RUN chown -R monitor:monitor /app

# Switch to non-root user
USER monitor

# Expose metrics port
EXPOSE 8800

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8800/health || exit 1

# Run application
CMD ["./ebpf-monitor"]