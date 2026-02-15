# pac-proxy Design Document

**Date:** 2026-02-16
**Status:** Approved

## Overview

pac-proxy is a forward HTTP/HTTPS proxy server written in Go that uses a PAC file to determine routing decisions. It forwards traffic either directly to the destination or via an upstream proxy. Targets RHEL 8, distributed as an RPM via GoReleaser, runs as a systemd service.

## Project Structure

```
pac-proxy/
├── cmd/pac-proxy/
│   └── main.go              # Flag parsing, signal handling, wiring
├── internal/
│   ├── pac/
│   │   ├── loader.go        # Load PAC from file or URL, reload on SIGHUP
│   │   └── evaluator.go     # Wraps gpac.FindProxyForURL, parses result
│   ├── proxy/
│   │   ├── handler.go       # HTTP handler: routes to forward or tunnel
│   │   ├── forward.go       # HTTP request forwarding (direct or upstream)
│   │   └── tunnel.go        # CONNECT tunnel (blind TCP relay)
│   ├── metrics/
│   │   └── metrics.go       # Prometheus metric definitions
│   └── logging/
│       └── logging.go       # slog-to-syslog setup, request logging
├── packaging/
│   ├── pac-proxy.service     # systemd unit
│   └── pac.sysconfig         # /etc/sysconfig/pac template
├── .goreleaser.yaml
├── go.mod
└── go.sum
```

## Technical Decisions

| Decision | Choice | Rationale |
|---|---|---|
| HTTP handling | `net/http.Server` + `Hijack` for CONNECT | Standard, well-tested Go proxy pattern |
| HTTP forwarding | Manual `http.Transport.RoundTrip` | Full control over hop-by-hop headers and upstream routing |
| PAC evaluation | `github.com/darren/gpac` | Pure Go, MIT licensed, uses otto JS engine |
| Logging | `log/slog` with syslog writer | Stdlib, structured, zero extra deps |
| Metrics | `prometheus/client_golang` | Required by spec |
| Graceful shutdown | `context` + `http.Server.Shutdown` | Standard pattern |

## Component Details

### PAC Loader/Evaluator

The loader reads from a file path or HTTP URL. It holds a `sync.RWMutex`-protected reference to the current `gpac.Parser`. On SIGHUP, it reloads and swaps the parser atomically. The evaluator calls `FindProxyForURL(url, host)` and parses the result string into a structured type (`Direct` or `Proxy{host, port}`).

### Proxy Handler

A single `http.Handler` checks the method. CONNECT requests go to the tunnel path; everything else goes to the forward path. Both paths call the PAC evaluator first to determine routing.

### Forward Handler

Strips hop-by-hop headers, creates a new `http.Request`, dials either direct or through the upstream proxy using a custom `http.Transport`, copies the response back to the client. Tracks bytes and duration for metrics/logging.

### Tunnel Handler

Hijacks the connection, dials the target (direct or via upstream CONNECT), sends `200 Connection Established`, then uses `io.Copy` in both directions with a `sync.WaitGroup`. For upstream proxy tunnelling, it sends a CONNECT request to the upstream first.

### Metrics

All metrics defined as package-level vars in `internal/metrics`. The handler and tunnel code call increment/observe functions directly. Prometheus endpoint served on a separate `http.Server` on the metrics port.

### Signal Handling

`main.go` sets up `signal.Notify` for SIGHUP (reload PAC), SIGTERM/SIGINT (graceful shutdown via context cancellation and `server.Shutdown`).

## Configuration

- `PAC_FILE` environment variable (required): path or URL to PAC file
- `-listen` flag (default `:3128`): proxy listen address
- `-metrics` flag (default `:9128`): metrics endpoint address

## Dependencies

- `github.com/darren/gpac` — PAC file parsing and evaluation
- `github.com/prometheus/client_golang` — Prometheus metrics
- Go 1.21+ (for `log/slog`)
