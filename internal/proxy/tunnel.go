package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gary/pac-proxy/internal/logging"
	"github.com/gary/pac-proxy/internal/metrics"
)

func (h *Handler) handleTunnel(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	metrics.ActiveConnections.Inc()
	defer metrics.ActiveConnections.Dec()

	host := r.Host

	// Synthesise URL for PAC evaluation per spec
	pacURL := fmt.Sprintf("https://%s/", host)
	route, err := h.pac.Evaluate(pacURL, hostOnly(host))
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

	// Dial the target (direct or via upstream proxy)
	var targetConn net.Conn
	if route.Direct {
		targetConn, err = net.DialTimeout("tcp", host, 30*time.Second)
	} else {
		targetConn, err = dialViaUpstream(route.ProxyAddress, host)
	}
	if err != nil {
		h.logger.Error("dial failed", "error", err, "target", host, "upstream", upstream)
		if !route.Direct {
			metrics.UpstreamErrors.WithLabelValues(upstream).Inc()
		}
		http.Error(w, "failed to connect", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Hijack the client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		h.logger.Error("hijack not supported")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		h.logger.Error("hijack failed", "error", err)
		return
	}
	defer clientConn.Close()

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy
	var wg sync.WaitGroup
	var bytesSent, bytesRecv int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		bytesSent, _ = io.Copy(clientConn, targetConn)
	}()
	go func() {
		defer wg.Done()
		bytesRecv, _ = io.Copy(targetConn, clientConn)
	}()
	wg.Wait()

	duration := time.Since(start)
	domain := hostOnly(host)

	metrics.RequestsTotal.WithLabelValues("CONNECT", domain, routeLabel).Inc()
	metrics.RequestDuration.WithLabelValues("CONNECT", routeLabel).Observe(duration.Seconds())
	metrics.RequestsByDomain.WithLabelValues(domain, routeLabel).Inc()
	metrics.BytesSent.WithLabelValues(routeLabel).Add(float64(bytesSent))
	metrics.BytesReceived.WithLabelValues(routeLabel).Add(float64(bytesRecv))

	pacResult := "DIRECT"
	if !route.Direct {
		pacResult = "PROXY " + route.ProxyAddress
	}

	logging.LogRequest(h.logger, logging.RequestEntry{
		ClientIP:   clientIP(r),
		Method:     "CONNECT",
		Host:       domain,
		URL:        host,
		PACResult:  pacResult,
		Upstream:   upstream,
		StatusCode: 200,
		Duration:   duration,
		BytesSent:  bytesSent,
		BytesRecv:  bytesRecv,
	})
}

// dialViaUpstream connects to the target through an upstream HTTP proxy
// by issuing a CONNECT request.
func dialViaUpstream(proxyAddr, targetHost string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", proxyAddr, err)
	}

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetHost, targetHost)

	// Read the proxy response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading upstream CONNECT response: %w", err)
	}

	response := string(buf[:n])
	if len(response) < 12 || response[9] != '2' {
		conn.Close()
		return nil, fmt.Errorf("upstream CONNECT failed: %s", response)
	}

	return conn, nil
}
