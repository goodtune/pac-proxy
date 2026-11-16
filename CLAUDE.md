# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
go build ./cmd/pac-proxy            # Build the binary
go test ./...                        # Run all tests
go test ./... -v                     # Verbose test output
go test ./... -race                  # With race detection
go test ./internal/proxy/ -run TestHandleForward  # Run a single test
go vet ./...                         # Lint
goreleaser release --snapshot --clean --skip=publish  # Build archives and RPM/DEB/APK packages into dist/
```

## Running Locally

```bash
export PAC_FILE=/path/to/proxy.pac
go run ./cmd/pac-proxy -listen :3128 -metrics :9128
```

Send `SIGHUP` to reload the PAC file without restart.

## Architecture

pac-proxy is a PAC-aware HTTP/HTTPS forward proxy. Clients connect to it, and it evaluates a PAC (Proxy Auto-Config) file to decide whether to route each request directly or via an upstream proxy.

### Package Layout

- **`cmd/pac-proxy/`** — Entry point. Wires together PAC evaluator, proxy handler, logging, and metrics. Handles signals (`SIGHUP` for PAC reload, `SIGTERM`/`SIGINT` for graceful shutdown).
- **`internal/pac/`** — Loads PAC files (from path or URL), evaluates `FindProxyForURL()` using `gpac` (JS engine). Thread-safe via `sync.RWMutex`.
- **`internal/proxy/`** — HTTP handler that routes `CONNECT` requests to `handleTunnel` and all other methods to `handleForward`. Uses a `PACEvaluator` interface for testability.
- **`internal/metrics/`** — Prometheus metric definitions (requests, duration, bytes, active connections, PAC reloads, upstream errors). Served on `:9128/metrics`.
- **`internal/logging/`** — Structured logging via `log/slog`. Exports over OTLP (via the OpenTelemetry `otelslog` bridge) when the standard `OTEL_*` environment configures it; otherwise writes to stderr, as text on a TTY and JSON elsewhere.
- **`packaging/`** — systemd unit file and sysconfig template for RPM deployment.

### Key Patterns

- **Adapter pattern**: `cmd/pac-proxy/main.go` defines `pacAdapter` to convert between `pac.Result` and `proxy.Route`, keeping the packages decoupled.
- **Interface-based testing**: `internal/proxy` defines `PACEvaluator` interface; tests use `mockEvaluator`.
- **Table-driven tests**: All test files use the `[]struct{ name string; ... }` + `t.Run` pattern.

## Configuration

- `PAC_FILE` env var (required) — path or URL to a PAC file
- `-listen` flag — proxy address (default `:3128`)
- `-metrics` flag — metrics address (default `:9128`)
- `-version` flag — print the version and exit
- `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`, or `OTEL_LOGS_EXPORTER=otlp`) — send logs to an OTLP collector; `OTEL_EXPORTER_OTLP_PROTOCOL` picks `http/protobuf` (default) or `grpc`
