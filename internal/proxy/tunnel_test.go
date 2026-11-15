package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/goodtune/pac-proxy/internal/proxy"
)

func TestConnectTunnelDirect(t *testing.T) {
	// TLS origin server
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("secure hello"))
	}))
	defer origin.Close()

	eval := &mockEvaluator{route: proxy.Route{Direct: true}}
	handler := proxy.NewHandler(eval, nil)

	// Start a proxy server
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// A client that trusts the origin's certificate and sends CONNECT to the proxy
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := origin.Client()
	client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("request through tunnel failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure hello" {
		t.Errorf("body: got %q, want %q", body, "secure hello")
	}
}
