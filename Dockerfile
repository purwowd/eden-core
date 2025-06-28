# Build stage
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=docker" \
    -o eden ./cmd/eden

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    php \
    nodejs \
    npm \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Install Python cryptography library for protected Python files
RUN pip3 install --no-cache-dir cryptography

# Create non-root user
RUN addgroup -g 1001 eden && \
    adduser -D -s /bin/sh -u 1001 -G eden eden

# Create working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/eden /usr/local/bin/eden

# Make binary executable
RUN chmod +x /usr/local/bin/eden

# Switch to non-root user
USER eden

# Create directories for input/output
RUN mkdir -p /app/input /app/output

# Set default working directory
WORKDIR /app

# Create volumes for data persistence
VOLUME ["/app/protected", "/app/keys", "/app/backups"]

# Environment variables
ENV EDEN_LOG_LEVEL=info
ENV EDEN_LOG_FORMAT=json
ENV EDEN_STORAGE_BASE_PATH=/app/protected
ENV EDEN_KEY_DIR=/app/keys
ENV EDEN_BACKUP_DIR=/app/backups
ENV EDEN_TEMP_DIR=/tmp/eden

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD eden -help || exit 1

# Default command
ENTRYPOINT ["eden"]
CMD ["--help"]

# Labels for metadata
LABEL maintainer="Eden Core Team <support@purwowd.com>"
LABEL version="1.0.0"
LABEL description="Universal Source Code Protection System with Cryptocurrency-Grade Security"
LABEL org.opencontainers.image.source="https://github.com/purwowd/eden-core"
LABEL org.opencontainers.image.documentation="https://github.com/purwowd/eden-core/README.md"
LABEL org.opencontainers.image.licenses="MIT" 
