package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"golang.org/x/term"
)

const serviceName = "pac-proxy"

// RequestEntry holds all fields for a proxy request log line.
type RequestEntry struct {
	ClientIP   string
	Method     string
	Host       string
	URL        string
	PACResult  string
	Upstream   string
	StatusCode int
	Duration   time.Duration
	BytesSent  int64
	BytesRecv  int64
}

// LogRequest logs a proxy request with structured fields.
func LogRequest(logger *slog.Logger, e RequestEntry) {
	logger.Info("proxy request",
		"client_ip", e.ClientIP,
		"method", e.Method,
		"host", e.Host,
		"url", e.URL,
		"pac_result", e.PACResult,
		"upstream", e.Upstream,
		"status_code", e.StatusCode,
		"duration_ms", e.Duration.Milliseconds(),
		"bytes_sent", e.BytesSent,
		"bytes_received", e.BytesRecv,
	)
}

// New returns the process logger and a shutdown function that flushes it.
//
// When the standard OpenTelemetry environment asks for OTLP log export
// (OTEL_LOGS_EXPORTER=otlp, or an OTEL_EXPORTER_OTLP_ENDPOINT or
// OTEL_EXPORTER_OTLP_LOGS_ENDPOINT), records go to an OTLP collector over
// the protocol in OTEL_EXPORTER_OTLP_(LOGS_)PROTOCOL: http/protobuf (the
// default) or grpc. The exporters read the rest of the OTEL_EXPORTER_OTLP_*
// settings themselves, and OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES
// override the resource.
//
// Otherwise records go to stderr: text on a terminal, JSON elsewhere (for
// example under systemd, where the journal collects them).
func New(ctx context.Context, version string) (*slog.Logger, func(context.Context) error, error) {
	if !otlpEnabled() {
		return slog.New(stderrHandler(os.Stderr)), func(context.Context) error { return nil }, nil
	}

	exporter, err := newExporter(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Later options win, so the environment overrides these defaults.
	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
			attribute.String("service.version", version),
		),
		resource.WithFromEnv(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("building OpenTelemetry resource: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)
	logger := otelslog.NewLogger(serviceName,
		otelslog.WithLoggerProvider(provider),
		otelslog.WithVersion(version),
	)
	return logger, provider.Shutdown, nil
}

// otlpEnabled reports whether the environment asks for OTLP log export.
func otlpEnabled() bool {
	switch os.Getenv("OTEL_LOGS_EXPORTER") {
	case "otlp":
		return true
	case "":
		return os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") != "" ||
			os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != ""
	default: // "none", or an exporter this binary does not ship
		return false
	}
}

func newExporter(ctx context.Context) (sdklog.Exporter, error) {
	protocol := os.Getenv("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL")
	if protocol == "" {
		protocol = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}

	switch protocol {
	case "", "http/protobuf":
		return otlploghttp.New(ctx)
	case "grpc":
		return otlploggrpc.New(ctx)
	default:
		return nil, fmt.Errorf("unsupported OTLP protocol %q: use http/protobuf or grpc", protocol)
	}
}

func stderrHandler(f *os.File) slog.Handler {
	if term.IsTerminal(int(f.Fd())) {
		return slog.NewTextHandler(f, nil)
	}
	return slog.NewJSONHandler(f, nil)
}
