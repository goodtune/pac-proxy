package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pac_proxy_requests_total",
			Help: "Total number of proxied requests.",
		},
		[]string{"method", "domain", "route"},
	)

	RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "pac_proxy_request_duration_seconds",
			Help:    "Request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "route"},
	)

	RequestsByDomain = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pac_proxy_requests_by_domain_total",
			Help: "Request count per destination domain.",
		},
		[]string{"domain", "route"},
	)

	BytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pac_proxy_bytes_sent_total",
			Help: "Total bytes sent to clients.",
		},
		[]string{"route"},
	)

	BytesReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pac_proxy_bytes_received_total",
			Help: "Total bytes received from clients.",
		},
		[]string{"route"},
	)

	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "pac_proxy_active_connections",
			Help: "Number of currently active proxy connections.",
		},
	)

	PACReloadTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pac_proxy_pac_reload_total",
			Help: "Count of PAC file reloads.",
		},
		[]string{"status"},
	)

	UpstreamErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pac_proxy_upstream_errors_total",
			Help: "Count of errors connecting to upstream proxies.",
		},
		[]string{"upstream"},
	)
)

// All collects all metrics for registration.
func All() []prometheus.Collector {
	return []prometheus.Collector{
		RequestsTotal,
		RequestDuration,
		RequestsByDomain,
		BytesSent,
		BytesReceived,
		ActiveConnections,
		PACReloadTotal,
		UpstreamErrors,
	}
}

// RegisterOn registers all metrics on the given registry.
func RegisterOn(reg prometheus.Registerer) {
	for _, c := range All() {
		reg.MustRegister(c)
	}
}

// Register registers all metrics on the default registry.
func Register() {
	RegisterOn(prometheus.DefaultRegisterer)
}
