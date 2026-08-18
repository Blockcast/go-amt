# Static, pure-Go receiver image for validator operators.
#
# The build stage tracks the toolchain floor in go.mod (go 1.24.0) rather than
# "latest", so a rebuild cannot silently jump a major Go version. Note what this
# does NOT buy: `1.24-bookworm` is a floating patch tag, so a rebuild picks up
# whatever 1.24.x is current and the output is not byte-identical — `-trimpath`
# removes path nondeterminism, not toolchain nondeterminism. That is the
# deliberate trade: patch-level Go security fixes on rebuild, in exchange for
# reproducibility. For a byte-identical rebuild, override the tag with a digest:
#
#   docker build --build-arg GO_VERSION=1.24.0 .
#
ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

# Dependencies resolve in their own layer so a source-only edit does not
# re-download the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 is the deliverable, not an optimisation: the customer install
# is one static binary that must not link against the host's libc. -s -w strip
# the symbol and DWARF tables, which is safe here because the receiver reports
# faults through slog and metrics rather than through core dumps.
#
# No -X version stamp is set. goreleaser's default ldflags would inject
# -X main.version, and package main has no such symbol, so the linker would
# silently discard it and the image would claim a version it cannot report.
# The version string lands with the broker lane (go-amt#45), which owns the
# field-rollback lever; see docs/operations/install.md.
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/blockcast-shreds ./cmd/blockcast-shreds

# distroless/static carries CA certificates and /etc/passwd. The receiver needs
# neither today, but the broker lane terminates mTLS to a public endpoint, so
# starting from scratch would mean swapping the base image at exactly the moment
# certificate handling arrives.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/blockcast-shreds /usr/local/bin/blockcast-shreds

# Ingress feed, then the metrics/health endpoint. Both are above 1024 so the
# container needs no capabilities and runs as the base image's nonroot user.
EXPOSE 20000/udp
EXPOSE 8080/tcp
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/blockcast-shreds"]
# Bind the HTTP endpoint to all interfaces: the 127.0.0.1 default is correct for
# a host install and unreachable from outside a container.
CMD ["--http-addr", "0.0.0.0:8080", "--listen", "0.0.0.0:20000"]
