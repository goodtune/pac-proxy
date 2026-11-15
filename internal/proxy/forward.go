package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"

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

// routeKey is the context key under which handleForward passes the Route
// to the shared transport.
type routeKey struct{}

// proxyForRoute is the transport's Proxy func. It sends the request via the
// upstream proxy of the Route in its context, or direct.
func proxyForRoute(r *http.Request) (*url.URL, error) {
	if route, ok := r.Context().Value(routeKey{}).(Route); ok && !route.Direct {
		return &url.URL{Scheme: "http", Host: route.ProxyAddress}, nil
	}
	return nil, nil
}

func (h *Handler) handleForward(w http.ResponseWriter, r *http.Request, route Route) (logging.RequestEntry, bool) {
	// Clone the request for forwarding
	outReq := r.Clone(context.WithValue(r.Context(), routeKey{}, route))
	outReq.RequestURI = ""
	removeHopByHop(outReq.Header)

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		h.logger.Error("upstream request failed", "error", err, "upstream", route.upstream())
		if !route.Direct {
			metrics.UpstreamErrors.WithLabelValues(route.upstream()).Inc()
		}
		http.Error(w, "upstream error", http.StatusBadGateway)
		return logging.RequestEntry{}, false
	}
	defer resp.Body.Close()

	removeHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	bytesSent, _ := io.Copy(w, resp.Body)

	return logging.RequestEntry{
		URL:        r.URL.String(),
		StatusCode: resp.StatusCode,
		BytesSent:  bytesSent,
	}, true
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
