package metrics_test

import (
	"strings"
	"testing"

	"github.com/goodtune/pac-proxy/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsRegistered(t *testing.T) {
	// Create a fresh registry to avoid pollution
	reg := prometheus.NewRegistry()
	metrics.RegisterOn(reg)

	ch := make(chan *prometheus.Desc, 32)
	go func() {
		for _, c := range metrics.All() {
			c.Describe(ch)
		}
		close(ch)
	}()

	var descs []string
	for desc := range ch {
		descs = append(descs, desc.String())
	}

	expected := []string{
		"pac_proxy_requests_total",
		"pac_proxy_request_duration_seconds",
		"pac_proxy_requests_by_domain_total",
		"pac_proxy_bytes_sent_total",
		"pac_proxy_bytes_received_total",
		"pac_proxy_active_connections",
		"pac_proxy_pac_reload_total",
		"pac_proxy_upstream_errors_total",
	}

	for _, name := range expected {
		t.Run(name, func(t *testing.T) {
			for _, d := range descs {
				if strings.Contains(d, name) {
					return
				}
			}
			t.Errorf("metric %q not registered", name)
		})
	}
}
