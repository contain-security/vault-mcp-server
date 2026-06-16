# Copyright IBM Corp. 2025, 2026
# SPDX-License-Identifier: MPL-2.0

# This Dockerfile contains multiple targets.
# Use 'docker build --target=<name> .' to build one.

# ===================================
#
#   Non-release images.
#
# ===================================

# certbuild captures the ca-certificates
FROM alpine:3.22@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 AS certbuild
RUN apk add --no-cache ca-certificates

# devbuild compiles the binary
# -----------------------------------
FROM golang:1.25.11-alpine@sha256:8d95af53d0d58e1759ddb4028285d9b1239067e4fbf4f544618cad0f60fbc354 AS devbuild
ARG VERSION="dev"
# Set the working directory
WORKDIR /build
RUN go env -w GOMODCACHE=/root/.cache/go-build
# Install dependencies
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build go mod download
COPY . ./
# Build the server
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/hashicorp/vault-mcp-server/version.GitCommit=$(shell git rev-parse HEAD) -X github.com/hashicorp/vault-mcp-server/version.BuildDate=$(shell git show --no-show-signature -s --format=%cd --date=format:'%Y-%m-%dT%H:%M:%SZ' HEAD)" \
    -o vault-mcp-server ./cmd/vault-mcp-server

# dev runs the binary from devbuild
# -----------------------------------
# Run the app on a full Alpine base (gives a shell + apk for debugging) instead
# of scratch. ca-certificates come from the distro rather than the certbuild
# stage, and the server runs as a non-root user.
FROM alpine:3.22@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 AS dev
ARG VERSION="dev"
RUN apk add --no-cache ca-certificates \
    && addgroup -S vault-mcp \
    && adduser -S -G vault-mcp -h /server vault-mcp
# Set the working directory
WORKDIR /server
# Copy the binary from the build stage
COPY --from=devbuild /build/vault-mcp-server .
USER vault-mcp
# Command to run the server
CMD ["./vault-mcp-server", "stdio"]

# ===================================
#
#   Release images that uses CI built binaries (CRT generated)
#
# ===================================

# default release image (refereced in .github/workflows/build.yml)
# -----------------------------------
FROM scratch AS release-default
ARG BIN_NAME
# Export BIN_NAME for the CMD below, it can't see ARGs directly.
ENV BIN_NAME=$BIN_NAME
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=$BIN_NAME
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH
LABEL version=$PRODUCT_VERSION
LABEL revision=$PRODUCT_REVISION
COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /bin/vault-mcp-server
COPY --from=certbuild /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
CMD ["/bin/vault-mcp-server", "stdio"]

# ===================================
#
#   Set default target to 'dev'.
#
# ===================================
FROM dev
