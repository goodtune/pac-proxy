package test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goodtune/pac-proxy/internal/pac"
	"github.com/goodtune/pac-proxy/internal/proxy"
)

type e2eAdapter struct {
	eval *pac.Evaluator
}

func (a *e2eAdapter) Evaluate(u, host string) (proxy.Route, error) {
	result, err := a.eval.Evaluate(u, host)
	if err != nil {
		return proxy.Route{}, err
	}
	return proxy.Route{
		Direct:       result.Direct,
		ProxyAddress: result.ProxyAddress,
	}, nil
}

func TestEndToEndHTTP(t *testing.T) {
	// Origin server
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("e2e ok"))
	}))
	defer origin.Close()

	// Upstream proxy
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer upstream.Close()

	upstreamAddr := upstream.Listener.Addr().String()

	tests := []struct {
		name      string
		pacResult string
	}{
		{
			name:      "direct",
			pacResult: "DIRECT",
		},
		{
			name:      "via upstream",
			pacResult: "PROXY " + upstreamAddr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			pacPath := filepath.Join(dir, "test.pac")
			pacContent := `function FindProxyForURL(url, host) { return "` + tt.pacResult + `"; }`
			os.WriteFile(pacPath, []byte(pacContent), 0644)

			eval, err := pac.New(pacPath)
			if err != nil {
				t.Fatal(err)
			}

			handler := proxy.NewHandler(&e2eAdapter{eval: eval}, nil)
			proxyServer := httptest.NewServer(handler)
			defer proxyServer.Close()

			proxyURL, _ := url.Parse(proxyServer.URL)
			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				},
				Timeout: 5 * time.Second,
			}

			resp, err := client.Get(origin.URL + "/test")
			if err != nil {
				t.Fatalf("request through proxy failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				t.Errorf("status: got %d, want 200", resp.StatusCode)
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "e2e ok" {
				t.Errorf("body: got %q, want %q", body, "e2e ok")
			}
		})
	}
}
