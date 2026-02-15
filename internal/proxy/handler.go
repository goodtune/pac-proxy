package proxy

import (
	"log/slog"
	"net/http"
)

// Route represents a PAC evaluation result.
type Route struct {
	Direct       bool
	ProxyAddress string // host:port of upstream proxy
}

// PACEvaluator evaluates a URL against PAC rules.
type PACEvaluator interface {
	Evaluate(url, host string) (Route, error)
}

// Handler is the main proxy HTTP handler.
type Handler struct {
	pac    PACEvaluator
	logger *slog.Logger
}

// NewHandler creates a new proxy handler.
func NewHandler(pac PACEvaluator, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{pac: pac, logger: logger}
}

// ServeHTTP routes requests to the appropriate handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleTunnel(w, r)
		return
	}
	h.handleForward(w, r)
}
