# Build stage
FROM rust:1.75-slim as builder

WORKDIR /app

# Install required system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY migrations ./migrations

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -u 1000 -m -c "lark messager user" -d /app -s /bin/bash lark_messager && \
    chmod 755 /app

WORKDIR /app

# Copy the built binary
COPY --from=builder /app/target/release/lark_messager .

# Copy migrations
COPY --from=builder /app/migrations ./migrations

# Change ownership
RUN chown -R lark_messager:lark_messager /app

# Switch to non-root user
USER lark_messager

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the binary
CMD ["./lark_messager"]