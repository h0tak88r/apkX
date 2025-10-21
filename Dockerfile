# apkX Web - Docker image (v3.3)
# Builds the server and bundles all required tools

FROM golang:1.22-bookworm as builder

# System deps for build and runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    unzip zip curl git ca-certificates python3 python3-pip \
    wget build-essential \
    libssl3 libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Optional tools: install apk-mitm (Node) and apkeep binary
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && npm install -g apk-mitm \
    && rm -rf /var/lib/apt/lists/*

# Install JADX decompiler
RUN set -eux; \
    JADX_VERSION="1.4.7"; \
    curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip; \
    unzip /tmp/jadx.zip -d /tmp/; \
    mkdir -p /opt/jadx; \
    mv /tmp/bin /tmp/lib /tmp/LICENSE /tmp/README.md /tmp/NOTICE /opt/jadx/; \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx; \
    rm /tmp/jadx.zip

# Install apkeep by downloading prebuilt binary (no PyPI package)
RUN set -eux; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
      amd64)  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/0.17.0/apkeep-x86_64-unknown-linux-gnu" ;; \
      arm64)  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/0.17.0/apkeep-aarch64-unknown-linux-gnu" ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac; \
    curl -fsSL "$APKEEP_URL" -o /usr/local/bin/apkeep; \
    chmod +x /usr/local/bin/apkeep

# Install ipatool for iOS downloads
RUN set -eux; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
      amd64)  IPATOOL_URL="https://github.com/majd/ipatool/releases/download/v2.2.0/ipatool-2.2.0-linux-amd64.tar.gz" ;; \
      arm64)  IPATOOL_URL="https://github.com/majd/ipatool/releases/download/v2.2.0/ipatool-2.2.0-linux-arm64.tar.gz" ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac; \
    curl -fsSL "$IPATOOL_URL" -o /tmp/ipatool.tar.gz; \
    tar -xzf /tmp/ipatool.tar.gz -C /tmp/; \
    mv /tmp/bin/ipatool-2.2.0-linux-${ARCH} /usr/local/bin/ipatool; \
    chmod +x /usr/local/bin/ipatool; \
    rm /tmp/ipatool.tar.gz

WORKDIR /app

# Cache go mod first
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build web server
RUN go build -o apkx-web ./cmd/server/main.go

# Final image
FROM debian:bookworm-slim

ENV PORT=9090

# Runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    unzip zip curl ca-certificates python3 python3-pip \
    wget build-essential \
    libssl3 libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js and apk-mitm
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && npm install -g apk-mitm \
    && rm -rf /var/lib/apt/lists/*

# Install JADX decompiler
RUN set -eux; \
    JADX_VERSION="1.4.7"; \
    curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip; \
    unzip /tmp/jadx.zip -d /tmp/; \
    mkdir -p /opt/jadx; \
    mv /tmp/bin /tmp/lib /tmp/LICENSE /tmp/README.md /tmp/NOTICE /opt/jadx/; \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx; \
    rm /tmp/jadx.zip

# Install apkeep binary
RUN set -eux; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
      amd64)  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/0.17.0/apkeep-x86_64-unknown-linux-gnu" ;; \
      arm64)  APKEEP_URL="https://github.com/EFForg/apkeep/releases/download/0.17.0/apkeep-aarch64-unknown-linux-gnu" ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac; \
    curl -fsSL "$APKEEP_URL" -o /usr/local/bin/apkeep; \
    chmod +x /usr/local/bin/apkeep

# Install ipatool for iOS downloads
RUN set -eux; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
      amd64)  IPATOOL_URL="https://github.com/majd/ipatool/releases/download/v2.2.0/ipatool-2.2.0-linux-amd64.tar.gz" ;; \
      arm64)  IPATOOL_URL="https://github.com/majd/ipatool/releases/download/v2.2.0/ipatool-2.2.0-linux-arm64.tar.gz" ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac; \
    curl -fsSL "$IPATOOL_URL" -o /tmp/ipatool.tar.gz; \
    tar -xzf /tmp/ipatool.tar.gz -C /tmp/; \
    mv /tmp/bin/ipatool-2.2.0-linux-${ARCH} /usr/local/bin/ipatool; \
    chmod +x /usr/local/bin/ipatool; \
    rm /tmp/ipatool.tar.gz

WORKDIR /app

# App files
COPY --from=builder /app/apkx-web /usr/local/bin/apkx-web
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
# Copy config file as fallback (will be overridden by volume mount if available)
COPY config/regexes.yaml /app/config/regexes.yaml
# Ensure runtime data directories exist inside the image
RUN mkdir -p /app/web-data/uploads /app/web-data/downloads /app/web-data/reports /app/config

EXPOSE ${PORT:-9090}

# Default command: use entrypoint script
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["-addr", ":9090", "-mitm"]
