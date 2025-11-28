# Build stage
FROM nimlang/nim:2.2.0-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    gcc \
    musl-dev \
    postgresql-dev \
    libsecp256k1-dev

WORKDIR /app

# Copy project files
COPY src ./src
COPY nim_nostr_relay.nimble .
COPY public ./public

# Install dependencies
RUN nimble install -y -d

# Build the application
RUN nimble build -d:release --opt:size

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    libpq \
    libsecp256k1 \
    libgcc \
    libstdc++

WORKDIR /app

# Copy binary and public files from builder
COPY --from=builder /app/nim-nostr-relay .
COPY public ./public

# Expose port
EXPOSE 9001

# Run the relay
CMD ["/app/nim-nostr-relay"]
