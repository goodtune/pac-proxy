package logging_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/goodtune/pac-proxy/internal/logging"
)

func TestLogRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	entry := logging.RequestEntry{
		ClientIP:   "192.168.1.1",
		Method:     "GET",
		Host:       "example.com",
		URL:        "http://example.com/path",
		PACResult:  "PROXY squid:3128",
		Upstream:   "squid:3128",
		StatusCode: 200,
		Duration:   150 * time.Millisecond,
		BytesSent:  1024,
		BytesRecv:  512,
	}

	logging.LogRequest(logger, entry)

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON log output: %v", err)
	}

	checks := map[string]any{
		"client_ip":      "192.168.1.1",
		"method":         "GET",
		"host":           "example.com",
		"url":            "http://example.com/path",
		"pac_result":     "PROXY squid:3128",
		"upstream":       "squid:3128",
		"status_code":    float64(200),
		"bytes_sent":     float64(1024),
		"bytes_received": float64(512),
	}

	for k, want := range checks {
		got, ok := m[k]
		if !ok {
			t.Errorf("missing field %q in log output", k)
			continue
		}
		if got != want {
			t.Errorf("field %q: got %v, want %v", k, got, want)
		}
	}

	if _, ok := m["duration_ms"]; !ok {
		t.Error("missing field duration_ms in log output")
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{
			name: "stderr when no OTLP settings",
		},
		{
			name: "OTLP over HTTP by default",
			env:  map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318"},
		},
		{
			name: "OTLP over gRPC",
			env: map[string]string{
				"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://127.0.0.1:4317",
				"OTEL_EXPORTER_OTLP_PROTOCOL":      "grpc",
			},
		},
		{
			name: "exporter disabled despite endpoint",
			env: map[string]string{
				"OTEL_LOGS_EXPORTER":          "none",
				"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318",
			},
		},
		{
			name: "unsupported protocol",
			env: map[string]string{
				"OTEL_LOGS_EXPORTER":          "otlp",
				"OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{
				"OTEL_LOGS_EXPORTER",
				"OTEL_EXPORTER_OTLP_ENDPOINT",
				"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
				"OTEL_EXPORTER_OTLP_PROTOCOL",
				"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
			} {
				t.Setenv(k, tt.env[k])
			}

			ctx := context.Background()
			logger, shutdown, err := logging.New(ctx, "test")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if logger == nil {
				t.Fatal("New returned a nil logger")
			}
			// No record is logged, so shutdown has nothing to send and must
			// not need a reachable collector.
			if err := shutdown(ctx); err != nil {
				t.Errorf("shutdown: %v", err)
			}
		})
	}
}
