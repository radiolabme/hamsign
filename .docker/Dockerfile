# hamsign - Go Development Container
#
# Multi-stage Dockerfile for building, testing, and cross-compiling Go projects.
# Supports cross-compilation for Windows, Linux, and macOS (multiple architectures).

# =============================================================================
# Stage 1: Builder base with all tools
# =============================================================================
FROM golang:1.25-bookworm AS builder-base

WORKDIR /workspace

# Install build dependencies for cross-compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    make \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install golangci-lint for linting
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
    sh -s -- -b /usr/local/bin v1.55.2

# Install goreleaser for release builds
RUN curl -sSfL https://github.com/goreleaser/goreleaser/releases/download/v1.24.0/goreleaser_Linux_x86_64.tar.gz | \
    tar -xz -C /usr/local/bin goreleaser

# =============================================================================
# Stage 2: Development environment
# =============================================================================
FROM builder-base AS dev

# Install additional dev tools
RUN go install golang.org/x/tools/gopls@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Default command for development
CMD ["make", "test"]

# =============================================================================
# Stage 3: CI environment (minimal, just for testing)
# =============================================================================
FROM builder-base AS ci

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Run tests by default
CMD ["make", "ci"]

# =============================================================================
# Stage 4: Build stage for producing binaries
# =============================================================================
FROM builder-base AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build with version information
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/hamsign-example ./example/...

# =============================================================================
# Stage 5: Minimal runtime image (for example binaries)
# =============================================================================
FROM gcr.io/distroless/static-debian12 AS runtime

COPY --from=build /out/ /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/hamsign-example"]
