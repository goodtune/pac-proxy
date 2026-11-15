package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/goodtune/pac-proxy/internal/logging"
	"github.com/goodtune/pac-proxy/internal/metrics"
)

const dialTimeout = 30 * time.Second

func (h *Handler) handleTunnel(w http.ResponseWriter, r *http.Request, route Route) (logging.RequestEntry, bool) {
	host := r.Host

	// Dial the target (direct or via upstream proxy)
	var targetConn net.Conn
	var err error
	if route.Direct {
		targetConn, err = net.DialTimeout("tcp", host, dialTimeout)
	} else {
		targetConn, err = dialViaUpstream(route.ProxyAddress, host)
	}
	if err != nil {
		h.logger.Error("dial failed", "error", err, "target", host, "upstream", route.upstream())
		if !route.Direct {
			metrics.UpstreamErrors.WithLabelValues(route.upstream()).Inc()
		}
		http.Error(w, "failed to connect", http.StatusBadGateway)
		return logging.RequestEntry{}, false
	}
	defer targetConn.Close()

	// Hijack the client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		h.logger.Error("hijack not supported")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return logging.RequestEntry{}, false
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		h.logger.Error("hijack failed", "error", err)
		return logging.RequestEntry{}, false
	}
	defer clientConn.Close()

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy: client to target in a goroutine, target to client here
	var bytesRecv int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		bytesRecv, _ = io.Copy(targetConn, clientConn)
	}()
	bytesSent, _ := io.Copy(clientConn, targetConn)
	<-done

	// Only a tunnel measures bytes received; ServeHTTP records the rest.
	metrics.BytesReceived.WithLabelValues(route.label()).Add(float64(bytesRecv))

	return logging.RequestEntry{
		URL:        host,
		StatusCode: http.StatusOK,
		BytesSent:  bytesSent,
		BytesRecv:  bytesRecv,
	}, true
}

// dialViaUpstream connects to the target through an upstream HTTP proxy
// by issuing a CONNECT request.
func dialViaUpstream(proxyAddr, targetHost string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, dialTimeout)
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
