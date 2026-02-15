package logging

import (
	"log/slog"
	"log/syslog"
	"time"
)

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

// NewSyslogLogger creates an slog.Logger that writes JSON to syslog.
// Falls back to a nil writer error if syslog is unavailable.
func NewSyslogLogger() (*slog.Logger, error) {
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "pac-proxy")
	if err != nil {
		return nil, err
	}
	return slog.New(slog.NewJSONHandler(w, nil)), nil
}
