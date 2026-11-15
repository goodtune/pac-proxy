package proxy

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/goodtune/pac-proxy/internal/logging"
	"github.com/goodtune/pac-proxy/internal/metrics"
)

// Route represents a PAC evaluation result.
type Route struct {
	Direct       bool
	ProxyAddress string // host:port of upstream proxy
}

// label is the value of the "route" metric label.
func (r Route) label() string {
	if r.Direct {
		return "direct"
	}
	return "forwarded"
}

// upstream names where the request was sent: the proxy address, or "direct".
func (r Route) upstream() string {
	if r.Direct {
		return "direct"
	}
	return r.ProxyAddress
}

// pacResult formats the route as a PAC directive.
func (r Route) pacResult() string {
	if r.Direct {
		return "DIRECT"
	}
	return "PROXY " + r.ProxyAddress
}

// PACEvaluator evaluates a URL against PAC rules.
type PACEvaluator interface {
	Evaluate(url string) (Route, error)
}

// Handler is the main proxy HTTP handler.
type Handler struct {
	pac       PACEvaluator
	logger    *slog.Logger
	transport *http.Transport
}

// NewHandler creates a new proxy handler.
func NewHandler(pac PACEvaluator, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		pac:    pac,
		logger: logger,
		transport: &http.Transport{
			Proxy:           proxyForRoute,
			IdleConnTimeout: 90 * time.Second,
		},
	}
}

// ServeHTTP evaluates the PAC route, hands the request to the forward or
// tunnel handler, and records metrics and the request log on success.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	metrics.ActiveConnections.Inc()
	defer metrics.ActiveConnections.Dec()

	serve, pacURL := h.handleForward, r.URL.String()
	if r.Method == http.MethodConnect {
		// Synthesise URL for PAC evaluation per spec
		serve, pacURL = h.handleTunnel, "https://"+r.Host+"/"
	}

	route, err := h.pac.Evaluate(pacURL)
	if err != nil {
		h.logger.Error("PAC evaluation failed", "error", err, "host", r.Host)
		http.Error(w, "PAC evaluation error", http.StatusBadGateway)
		return
	}

	// The handler fills in what only it knows: URL, status and byte counts.
	entry, ok := serve(w, r, route)
	if !ok {
		return
	}

	duration := time.Since(start)
	domain := hostOnly(r.Host)
	label := route.label()

	metrics.RequestsTotal.WithLabelValues(r.Method, domain, label).Inc()
	metrics.RequestDuration.WithLabelValues(r.Method, label).Observe(duration.Seconds())
	metrics.RequestsByDomain.WithLabelValues(domain, label).Inc()
	metrics.BytesSent.WithLabelValues(label).Add(float64(entry.BytesSent))

	entry.ClientIP = hostOnly(r.RemoteAddr)
	entry.Method = r.Method
	entry.Host = domain
	entry.PACResult = route.pacResult()
	entry.Upstream = route.upstream()
	entry.Duration = duration
	logging.LogRequest(h.logger, entry)
}
