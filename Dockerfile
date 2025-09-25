# syntax=docker/dockerfile:1.6

ARG RUST_VERSION=1.88

# Build stage
FROM rust:${RUST_VERSION}-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
COPY tests ./tests

RUN cargo fetch --locked
RUN cargo build --locked --release

# Runtime stage
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

ARG APP_USER=lark_messager
ARG APP_UID=1000
ARG APP_GID=1000

RUN groupadd -g ${APP_GID} ${APP_USER} && \
    useradd -r -u ${APP_UID} -g ${APP_GID} -m -d /app -s /usr/sbin/nologin ${APP_USER}

WORKDIR /app

COPY --from=builder /app/target/release/lark_messager /usr/local/bin/lark_messager
COPY --from=builder /app/migrations ./migrations

RUN chown -R ${APP_USER}:${APP_USER} /app

ENV RUST_LOG=info \
    APP_ENV=production

USER ${APP_USER}

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["/usr/local/bin/lark_messager"]
