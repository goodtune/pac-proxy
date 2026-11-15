package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/pac-proxy/internal/proxy"
)

// mockEvaluator implements proxy.PACEvaluator for testing.
type mockEvaluator struct {
	route proxy.Route
}

func (m *mockEvaluator) Evaluate(url string) (proxy.Route, error) {
	return m.route, nil
}

func TestForward(t *testing.T) {
	// Origin server
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hello from origin"))
	}))
	defer origin.Close()

	// Upstream proxy that forwards to origin
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	upstreamAddr := upstream.Listener.Addr().String()

	tests := []struct {
		name string
		eval *mockEvaluator
	}{
		{
			name: "direct",
			eval: &mockEvaluator{route: proxy.Route{Direct: true}},
		},
		{
			name: "via upstream",
			eval: &mockEvaluator{route: proxy.Route{ProxyAddress: upstreamAddr}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := proxy.NewHandler(tt.eval, nil)

			req := httptest.NewRequest("GET", origin.URL+"/path", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != 200 {
				t.Errorf("status: got %d, want 200", rec.Code)
			}
			if body := rec.Body.String(); body != "hello from origin" {
				t.Errorf("body: got %q, want %q", body, "hello from origin")
			}
		})
	}
}
