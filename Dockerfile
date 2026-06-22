# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Download dependencies first (layer cache friendly).
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a fully static binary.
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /logfort \
    ./cmd/logfort

# ---------------------------------------------------------------------------
# Final image — minimal alpine for health-check support.
# Switch to distroless/static when a native health-check binary is added.
# ---------------------------------------------------------------------------
FROM alpine:3.19

RUN apk --no-cache add ca-certificates wget && \
    addgroup -S logfort && adduser -S -G logfort logfort

COPY --from=builder /logfort /usr/local/bin/logfort

USER logfort:logfort

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:8080/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/logfort"]
