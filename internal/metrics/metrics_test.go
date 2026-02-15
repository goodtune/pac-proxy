package metrics_test

import (
	"testing"

	"github.com/goodtune/pac-proxy/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsRegistered(t *testing.T) {
	// Create a fresh registry to avoid pollution
	reg := prometheus.NewRegistry()
	metrics.RegisterOn(reg)

	// Use Describe to verify registration (Gather only returns observed metrics)
	expected := map[string]bool{
		"pac_proxy_requests_total":           false,
		"pac_proxy_request_duration_seconds": false,
		"pac_proxy_requests_by_domain_total": false,
		"pac_proxy_bytes_sent_total":         false,
		"pac_proxy_bytes_received_total":     false,
		"pac_proxy_active_connections":       false,
		"pac_proxy_pac_reload_total":         false,
		"pac_proxy_upstream_errors_total":    false,
	}

	ch := make(chan *prometheus.Desc, 32)
	go func() {
		for _, c := range metrics.All() {
			c.Describe(ch)
		}
		close(ch)
	}()

	for desc := range ch {
		name := desc.String()
		for eName := range expected {
			if contains(name, eName) {
				expected[eName] = true
			}
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("metric %q not registered", name)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
