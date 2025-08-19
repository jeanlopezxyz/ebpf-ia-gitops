# eBPF Monitor Application Dockerfile
FROM docker.io/library/golang:1.21-alpine AS builder

LABEL maintainer="eBPF AI Team"
LABEL description="eBPF-based network monitoring and metrics collection"

# Install build dependencies for eBPF
RUN apk add --no-cache git gcc musl-dev linux-headers clang llvm elfutils-dev bpftool libbpf-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Try to generate CO-RE vmlinux.h from host BTF if available (may fail during image build)
RUN mkdir -p bpf && (bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h || echo "no BTF on builder; continuing without CO-RE header")

# Generate eBPF Go bindings (if bpf2go is available)
# Generate eBPF Go bindings (if bpf2go is available). If it fails, runtime will fallback to simulation mode.
RUN go generate ./... || echo "bpf2go generation failed; will run in simulation mode if eBPF not available"

# Build application with eBPF support (auto-detect architecture)
RUN CGO_ENABLED=1 go build -a -installsuffix cgo -o ebpf-monitor ./cmd/monitor

# Final stage
FROM docker.io/library/alpine:latest

# Install runtime dependencies for eBPF
RUN apk add --no-cache ca-certificates curl iproute2

# Note: For eBPF, the container needs to run as root with privileges
# The security is handled by Kubernetes SecurityContext
# Create user but don't switch to it (eBPF requires root)
RUN adduser -D -s /bin/sh monitor

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/ebpf-monitor .

# eBPF programs would be copied here if generation succeeds
# COPY --from=builder /app/bpf/*.o ./bpf/ 2>/dev/null || true

# Note: Running as root for eBPF capabilities
# Security is enforced via Kubernetes RBAC and SecurityContext

# Expose metrics port
EXPOSE 8800

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8800/health || exit 1

# Run application
CMD ["./ebpf-monitor"]

# Defaults (can be overridden at runtime)
ENV HTTP_ADDR=:8800 \
    INTERFACE=eth0 \
    STATS_WINDOW=1s \
    POST_INTERVAL=2s \
    ML_DETECTOR_URL=http://ml-detector:5000 \
    HTTP_CLIENT_TIMEOUT=2s \
    LOG_LEVEL=info
