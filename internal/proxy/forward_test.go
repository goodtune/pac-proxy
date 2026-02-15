package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gary/pac-proxy/internal/proxy"
)

// mockEvaluator implements proxy.PACEvaluator for testing.
type mockEvaluator struct {
	direct bool
	addr   string
}

func (m *mockEvaluator) Evaluate(url, host string) (proxy.Route, error) {
	if m.direct {
		return proxy.Route{Direct: true}, nil
	}
	return proxy.Route{ProxyAddress: m.addr}, nil
}

func TestForwardDirect(t *testing.T) {
	// Origin server
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(200)
		w.Write([]byte("hello from origin"))
	}))
	defer origin.Close()

	eval := &mockEvaluator{direct: true}
	handler := proxy.NewHandler(eval, nil)

	// Simulate a forward proxy request (absolute URL)
	req := httptest.NewRequest("GET", origin.URL+"/path", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "hello from origin" {
		t.Errorf("body: got %q, want %q", body, "hello from origin")
	}
}

func TestForwardViaUpstream(t *testing.T) {
	// Origin server
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("from origin"))
	}))
	defer origin.Close()

	// Upstream proxy that forwards to origin (simplified: just proxies directly)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A real proxy would use the absolute URL; for testing, forward to origin
		resp, err := http.Get(origin.URL + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer upstream.Close()

	// Strip http:// prefix to get host:port
	upstreamAddr := upstream.Listener.Addr().String()
	eval := &mockEvaluator{direct: false, addr: upstreamAddr}
	handler := proxy.NewHandler(eval, nil)

	req := httptest.NewRequest("GET", origin.URL+"/path", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
}
