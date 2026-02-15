package proxy

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/goodtune/pac-proxy/internal/logging"
	"github.com/goodtune/pac-proxy/internal/metrics"
)

// Hop-by-hop headers that must not be forwarded.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func (h *Handler) handleForward(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	metrics.ActiveConnections.Inc()
	defer metrics.ActiveConnections.Dec()

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	route, err := h.pac.Evaluate(r.URL.String(), hostOnly(host))
	if err != nil {
		h.logger.Error("PAC evaluation failed", "error", err, "host", host)
		http.Error(w, "PAC evaluation error", http.StatusBadGateway)
		return
	}

	routeLabel := "direct"
	upstream := "direct"
	if !route.Direct {
		routeLabel = "forwarded"
		upstream = route.ProxyAddress
	}

	// Build transport
	transport := &http.Transport{}
	if !route.Direct {
		proxyURL := &url.URL{
			Scheme: "http",
			Host:   route.ProxyAddress,
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Clone the request for forwarding
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopByHop(outReq.Header)

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		h.logger.Error("upstream request failed", "error", err, "upstream", upstream)
		if !route.Direct {
			metrics.UpstreamErrors.WithLabelValues(upstream).Inc()
		}
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	bytesSent, _ := io.Copy(w, resp.Body)

	duration := time.Since(start)
	domain := hostOnly(host)

	metrics.RequestsTotal.WithLabelValues(r.Method, domain, routeLabel).Inc()
	metrics.RequestDuration.WithLabelValues(r.Method, routeLabel).Observe(duration.Seconds())
	metrics.RequestsByDomain.WithLabelValues(domain, routeLabel).Inc()
	metrics.BytesSent.WithLabelValues(routeLabel).Add(float64(bytesSent))

	pacResult := "DIRECT"
	if !route.Direct {
		pacResult = "PROXY " + route.ProxyAddress
	}

	logging.LogRequest(h.logger, logging.RequestEntry{
		ClientIP:   clientIP(r),
		Method:     r.Method,
		Host:       domain,
		URL:        r.URL.String(),
		PACResult:  pacResult,
		Upstream:   upstream,
		StatusCode: resp.StatusCode,
		Duration:   duration,
		BytesSent:  bytesSent,
	})
}

func removeHopByHop(h http.Header) {
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func hostOnly(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
