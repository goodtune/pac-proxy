package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/gary/pac-proxy/internal/logging"
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
