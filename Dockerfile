# ============================================================
# MCP-Lattice - Multi-stage Docker Build
# ============================================================

# ------ Builder Stage ------
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build arguments for version injection
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# Compile a statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w \
        -X github.com/panavinsingh/MCP-Lattice/internal/version.Version=${VERSION} \
        -X github.com/panavinsingh/MCP-Lattice/internal/version.Commit=${COMMIT} \
        -X github.com/panavinsingh/MCP-Lattice/internal/version.Date=${DATE}" \
    -o /bin/mcp-lattice \
    ./cmd/mcp-lattice

# ------ Final Stage ------
FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.title="mcp-lattice" \
      org.opencontainers.image.description="Security scanner for MCP (Model Context Protocol) servers" \
      org.opencontainers.image.url="https://github.com/panavinsingh/MCP-Lattice" \
      org.opencontainers.image.source="https://github.com/panavinsingh/MCP-Lattice" \
      org.opencontainers.image.licenses="Apache-2.0"

# Copy the binary from the builder stage
COPY --from=builder /bin/mcp-lattice /usr/local/bin/mcp-lattice

# Copy security check templates
COPY --from=builder /src/templates/ /templates/

# Run as non-root user (provided by distroless/static:nonroot)
USER nonroot:nonroot

ENTRYPOINT ["mcp-lattice"]
