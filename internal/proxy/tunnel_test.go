package proxy_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gary/pac-proxy/internal/proxy"
)

func TestConnectTunnelDirect(t *testing.T) {
	// TLS origin server
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("secure hello"))
	}))
	defer origin.Close()

	eval := &mockEvaluator{direct: true}
	handler := proxy.NewHandler(eval, nil)

	// Start a proxy server
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// Send CONNECT to proxy
	conn, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Extract host:port from origin
	originAddr := origin.Listener.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", originAddr, originAddr)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status: got %d, want 200", resp.StatusCode)
	}

	// Wrap in TLS and make request
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()

	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = originAddr
	req.Write(tlsConn)

	resp2, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("reading tunneled response: %v", err)
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)
	if string(body) != "secure hello" {
		t.Errorf("body: got %q, want %q", body, "secure hello")
	}
}
