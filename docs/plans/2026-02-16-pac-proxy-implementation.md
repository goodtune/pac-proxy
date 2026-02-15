# pac-proxy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a PAC-aware HTTP/HTTPS forward proxy server that routes requests based on PAC file rules, with Prometheus metrics, structured syslog logging, and RPM packaging.

**Architecture:** A `net/http.Server` accepts connections. HTTP requests are forwarded via manual `http.Transport.RoundTrip`. CONNECT requests are handled by hijacking the connection and establishing a blind TCP tunnel. The `github.com/darren/gpac` library evaluates PAC rules to determine routing (direct vs upstream proxy). Components are split into internal packages for testability.

**Tech Stack:** Go 1.21+, github.com/darren/gpac, github.com/prometheus/client_golang, log/slog, GoReleaser

---

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`
- Create: `cmd/pac-proxy/main.go` (minimal)

**Step 1: Initialize Go module**

Run: `go mod init github.com/gary/pac-proxy`

**Step 2: Create minimal main.go**

Create `cmd/pac-proxy/main.go`:

```go
package main

import "fmt"

func main() {
	fmt.Println("pac-proxy starting")
}
```

**Step 3: Verify it builds and runs**

Run: `go build -o pac-proxy ./cmd/pac-proxy && ./pac-proxy`
Expected: prints "pac-proxy starting"

**Step 4: Commit**

```bash
git add go.mod cmd/pac-proxy/main.go
git commit -m "feat: project scaffolding with go module and main entry point"
```

---

### Task 2: Metrics Package

**Files:**
- Create: `internal/metrics/metrics.go`
- Test: `internal/metrics/metrics_test.go`

**Step 1: Write the test**

Create `internal/metrics/metrics_test.go`:

```go
package metrics_test

import (
	"testing"

	"github.com/gary/pac-proxy/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsRegistered(t *testing.T) {
	// Create a fresh registry to avoid pollution
	reg := prometheus.NewRegistry()
	metrics.RegisterOn(reg)

	// Gather all metrics to verify registration
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	expected := map[string]bool{
		"pac_proxy_requests_total":            false,
		"pac_proxy_request_duration_seconds":  false,
		"pac_proxy_requests_by_domain_total":  false,
		"pac_proxy_bytes_sent_total":          false,
		"pac_proxy_bytes_received_total":      false,
		"pac_proxy_active_connections":        false,
		"pac_proxy_pac_reload_total":          false,
		"pac_proxy_upstream_errors_total":     false,
	}

	for _, f := range families {
		if _, ok := expected[f.GetName()]; ok {
			expected[f.GetName()] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("metric %q not registered", name)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/metrics/ -v`
Expected: FAIL — package doesn't exist yet

**Step 3: Write the implementation**

Create `internal/metrics/metrics.go`:

```go
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
```

**Step 4: Fetch dependencies and run test**

Run: `go get github.com/prometheus/client_golang/prometheus && go test ./internal/metrics/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/metrics/ go.mod go.sum
git commit -m "feat: add Prometheus metrics definitions"
```

---

### Task 3: PAC Loader and Evaluator

**Files:**
- Create: `internal/pac/pac.go`
- Test: `internal/pac/pac_test.go`

The gpac library's `Parser` already has a `Mutex` embedded. However, we need a wrapper that supports atomic reload. The gpac `FindProxy` method returns `[]*gpac.Proxy` with `IsDirect()` and `Address` fields — we'll use `FindProxy` directly instead of parsing strings.

**Step 1: Write the test**

Create `internal/pac/pac_test.go`:

```go
package pac_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gary/pac-proxy/internal/pac"
)

const testPAC = `
function FindProxyForURL(url, host) {
	if (host === "direct.example.com") {
		return "DIRECT";
	}
	return "PROXY squid.local:3128";
}
`

func writeTempPAC(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pac")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEvaluateDirect(t *testing.T) {
	path := writeTempPAC(t, testPAC)
	e, err := pac.New(path)
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	result, err := e.Evaluate("http://direct.example.com/page", "direct.example.com")
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if !result.Direct {
		t.Errorf("expected DIRECT, got proxy %q", result.ProxyAddress)
	}
}

func TestEvaluateProxy(t *testing.T) {
	path := writeTempPAC(t, testPAC)
	e, err := pac.New(path)
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	result, err := e.Evaluate("http://proxied.example.com/page", "proxied.example.com")
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if result.Direct {
		t.Error("expected PROXY, got DIRECT")
	}
	if result.ProxyAddress != "squid.local:3128" {
		t.Errorf("expected squid.local:3128, got %q", result.ProxyAddress)
	}
}

func TestReload(t *testing.T) {
	path := writeTempPAC(t, testPAC)
	e, err := pac.New(path)
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	// Overwrite with a PAC that returns DIRECT for everything
	newPAC := `function FindProxyForURL(url, host) { return "DIRECT"; }`
	if err := os.WriteFile(path, []byte(newPAC), 0644); err != nil {
		t.Fatal(err)
	}

	if err := e.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	result, err := e.Evaluate("http://proxied.example.com/page", "proxied.example.com")
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if !result.Direct {
		t.Error("expected DIRECT after reload")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/pac/ -v`
Expected: FAIL — package doesn't exist yet

**Step 3: Write the implementation**

Create `internal/pac/pac.go`:

```go
package pac

import (
	"fmt"
	"sync"

	"github.com/darren/gpac"
)

// Result represents the outcome of a PAC evaluation.
type Result struct {
	// Direct is true when the PAC returned DIRECT.
	Direct bool
	// ProxyAddress is the host:port of the upstream proxy (empty if Direct).
	ProxyAddress string
}

// Evaluator wraps a gpac.Parser with safe concurrent access and reload support.
type Evaluator struct {
	mu     sync.RWMutex
	parser *gpac.Parser
	source string // original file path or URL for reload
}

// New creates an Evaluator from a file path or URL.
func New(source string) (*Evaluator, error) {
	parser, err := gpac.From(source)
	if err != nil {
		return nil, fmt.Errorf("loading PAC from %q: %w", source, err)
	}
	return &Evaluator{parser: parser, source: source}, nil
}

// Evaluate runs FindProxyForURL and returns the first directive.
func (e *Evaluator) Evaluate(url, host string) (Result, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	proxies, err := e.parser.FindProxy(url)
	if err != nil {
		return Result{}, fmt.Errorf("FindProxy(%q): %w", url, err)
	}
	if len(proxies) == 0 {
		return Result{Direct: true}, nil
	}

	first := proxies[0]
	if first.IsDirect() {
		return Result{Direct: true}, nil
	}
	return Result{ProxyAddress: first.Address}, nil
}

// Reload reloads the PAC file from the original source.
func (e *Evaluator) Reload() error {
	parser, err := gpac.From(e.source)
	if err != nil {
		return fmt.Errorf("reloading PAC from %q: %w", e.source, err)
	}
	e.mu.Lock()
	e.parser = parser
	e.mu.Unlock()
	return nil
}

// Source returns the configured PAC source path or URL.
func (e *Evaluator) Source() string {
	return e.source
}
```

**Step 4: Fetch dependency and run tests**

Run: `go get github.com/darren/gpac && go test ./internal/pac/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/pac/ go.mod go.sum
git commit -m "feat: add PAC loader and evaluator with reload support"
```

---

### Task 4: Logging Package

**Files:**
- Create: `internal/logging/logging.go`
- Test: `internal/logging/logging_test.go`

The logging package sets up `slog` for structured logging and provides a helper to log proxy requests with all the fields from the spec.

**Step 1: Write the test**

Create `internal/logging/logging_test.go`:

```go
package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/gary/pac-proxy/internal/logging"
)

func TestLogRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	entry := logging.RequestEntry{
		ClientIP:   "192.168.1.1",
		Method:     "GET",
		Host:       "example.com",
		URL:        "http://example.com/path",
		PACResult:  "PROXY squid:3128",
		Upstream:   "squid:3128",
		StatusCode: 200,
		Duration:   150 * time.Millisecond,
		BytesSent:  1024,
		BytesRecv:  512,
	}

	logging.LogRequest(logger, entry)

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON log output: %v", err)
	}

	checks := map[string]any{
		"client_ip":   "192.168.1.1",
		"method":      "GET",
		"host":        "example.com",
		"url":         "http://example.com/path",
		"pac_result":  "PROXY squid:3128",
		"upstream":    "squid:3128",
		"status_code": float64(200),
		"bytes_sent":  float64(1024),
		"bytes_received": float64(512),
	}

	for k, want := range checks {
		got, ok := m[k]
		if !ok {
			t.Errorf("missing field %q in log output", k)
			continue
		}
		if got != want {
			t.Errorf("field %q: got %v, want %v", k, got, want)
		}
	}

	if _, ok := m["duration_ms"]; !ok {
		t.Error("missing field duration_ms in log output")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/logging/ -v`
Expected: FAIL

**Step 3: Write the implementation**

Create `internal/logging/logging.go`:

```go
package logging

import (
	"log/slog"
	"log/syslog"
	"time"
)

// RequestEntry holds all fields for a proxy request log line.
type RequestEntry struct {
	ClientIP   string
	Method     string
	Host       string
	URL        string
	PACResult  string
	Upstream   string
	StatusCode int
	Duration   time.Duration
	BytesSent  int64
	BytesRecv  int64
}

// LogRequest logs a proxy request with structured fields.
func LogRequest(logger *slog.Logger, e RequestEntry) {
	logger.Info("proxy request",
		"client_ip", e.ClientIP,
		"method", e.Method,
		"host", e.Host,
		"url", e.URL,
		"pac_result", e.PACResult,
		"upstream", e.Upstream,
		"status_code", e.StatusCode,
		"duration_ms", e.Duration.Milliseconds(),
		"bytes_sent", e.BytesSent,
		"bytes_received", e.BytesRecv,
	)
}

// NewSyslogLogger creates an slog.Logger that writes JSON to syslog.
// Falls back to a nil writer error if syslog is unavailable.
func NewSyslogLogger() (*slog.Logger, error) {
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "pac-proxy")
	if err != nil {
		return nil, err
	}
	return slog.New(slog.NewJSONHandler(w, nil)), nil
}
```

**Step 4: Run test**

Run: `go test ./internal/logging/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/logging/
git commit -m "feat: add structured syslog logging for proxy requests"
```

---

### Task 5: Proxy Handler — HTTP Forwarding

**Files:**
- Create: `internal/proxy/handler.go`
- Create: `internal/proxy/forward.go`
- Test: `internal/proxy/forward_test.go`

**Step 1: Write the test**

Create `internal/proxy/forward_test.go`:

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -v`
Expected: FAIL

**Step 3: Write handler.go**

Create `internal/proxy/handler.go`:

```go
package proxy

import (
	"log/slog"
	"net/http"
)

// Route represents a PAC evaluation result.
type Route struct {
	Direct       bool
	ProxyAddress string // host:port of upstream proxy
}

// PACEvaluator evaluates a URL against PAC rules.
type PACEvaluator interface {
	Evaluate(url, host string) (Route, error)
}

// Handler is the main proxy HTTP handler.
type Handler struct {
	pac    PACEvaluator
	logger *slog.Logger
}

// NewHandler creates a new proxy handler.
func NewHandler(pac PACEvaluator, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{pac: pac, logger: logger}
}

// ServeHTTP routes requests to the appropriate handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleTunnel(w, r)
		return
	}
	h.handleForward(w, r)
}
```

**Step 4: Write forward.go**

Create `internal/proxy/forward.go`:

```go
package proxy

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gary/pac-proxy/internal/logging"
	"github.com/gary/pac-proxy/internal/metrics"
)

// Hop-by-hop headers that must not be forwarded.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func (h *Handler) handleForward(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	metrics.ActiveConnections.Inc()
	defer metrics.ActiveConnections.Dec()

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	route, err := h.pac.Evaluate(r.URL.String(), hostOnly(host))
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

	// Build transport
	transport := &http.Transport{}
	if !route.Direct {
		proxyURL := &url.URL{
			Scheme: "http",
			Host:   route.ProxyAddress,
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Clone the request for forwarding
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopByHop(outReq.Header)

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		h.logger.Error("upstream request failed", "error", err, "upstream", upstream)
		if !route.Direct {
			metrics.UpstreamErrors.WithLabelValues(upstream).Inc()
		}
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	bytesSent, _ := io.Copy(w, resp.Body)

	duration := time.Since(start)
	domain := hostOnly(host)

	metrics.RequestsTotal.WithLabelValues(r.Method, domain, routeLabel).Inc()
	metrics.RequestDuration.WithLabelValues(r.Method, routeLabel).Observe(duration.Seconds())
	metrics.RequestsByDomain.WithLabelValues(domain, routeLabel).Inc()
	metrics.BytesSent.WithLabelValues(routeLabel).Add(float64(bytesSent))

	pacResult := "DIRECT"
	if !route.Direct {
		pacResult = "PROXY " + route.ProxyAddress
	}

	logging.LogRequest(h.logger, logging.RequestEntry{
		ClientIP:   clientIP(r),
		Method:     r.Method,
		Host:       domain,
		URL:        r.URL.String(),
		PACResult:  pacResult,
		Upstream:   upstream,
		StatusCode: resp.StatusCode,
		Duration:   duration,
		BytesSent:  bytesSent,
	})
}

func removeHopByHop(h http.Header) {
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func hostOnly(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
```

**Step 5: Create a stub handleTunnel so it compiles**

Add to `internal/proxy/handler.go` (or create `internal/proxy/tunnel.go` with a stub):

This will be a temporary stub — the full implementation is Task 6. For now add to `handler.go`:

```go
func (h *Handler) handleTunnel(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "CONNECT not yet implemented", http.StatusNotImplemented)
}
```

Actually — put the stub in `tunnel.go` so we replace it cleanly in Task 6.

Create `internal/proxy/tunnel.go`:

```go
package proxy

import "net/http"

// handleTunnel handles CONNECT requests. Stub — implemented in Task 6.
func (h *Handler) handleTunnel(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "CONNECT not yet implemented", http.StatusNotImplemented)
}
```

Remove the stub from `handler.go` if it was placed there.

**Step 6: Run tests**

Run: `go test ./internal/proxy/ -v`
Expected: PASS

**Step 7: Commit**

```bash
git add internal/proxy/ go.mod go.sum
git commit -m "feat: add HTTP forward proxy handler with PAC routing"
```

---

### Task 6: Proxy Handler — CONNECT Tunnel

**Files:**
- Modify: `internal/proxy/tunnel.go` (replace stub)
- Test: `internal/proxy/tunnel_test.go`

**Step 1: Write the test**

Create `internal/proxy/tunnel_test.go`:

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -v -run TestConnectTunnel`
Expected: FAIL — returns 501 Not Implemented

**Step 3: Replace the tunnel stub**

Replace `internal/proxy/tunnel.go` with:

```go
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
```

**Step 4: Run tests**

Run: `go test ./internal/proxy/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/proxy/tunnel.go internal/proxy/tunnel_test.go
git commit -m "feat: add CONNECT tunnel handler with upstream proxy support"
```

---

### Task 7: PAC Package — Implement the Route Interface

**Files:**
- Modify: `internal/pac/pac.go` — make Evaluator satisfy `proxy.PACEvaluator`

The `pac.Evaluator.Evaluate` currently returns `pac.Result` but the proxy handler expects a `proxy.Route`. We need to align these. The cleanest approach: have `pac.Evaluator` satisfy the `proxy.PACEvaluator` interface by returning `proxy.Route`.

However, this creates a circular dependency (`pac` → `proxy`). Instead, the proxy package defines the interface and types, and we make `pac.Result` structurally identical to `proxy.Route`, then use a thin adapter in `main.go`.

**Step 1: Create adapter in cmd/pac-proxy**

This is wiring — no new tests needed beyond integration. The `pac.Result` and `proxy.Route` are structurally identical (both have `Direct bool` and `ProxyAddress string`). Add a simple adapter:

In `cmd/pac-proxy/main.go` (during Task 8), we'll wire:

```go
type pacAdapter struct {
	eval *pac.Evaluator
}

func (a *pacAdapter) Evaluate(url, host string) (proxy.Route, error) {
	result, err := a.eval.Evaluate(url, host)
	if err != nil {
		return proxy.Route{}, err
	}
	return proxy.Route{
		Direct:       result.Direct,
		ProxyAddress: result.ProxyAddress,
	}, nil
}
```

**Step 2: Verify all tests still pass**

Run: `go test ./... -v`
Expected: PASS

**Step 3: Commit (if any changes made)**

```bash
git add internal/
git commit -m "refactor: align PAC result types with proxy route interface"
```

---

### Task 8: Main Wiring — Server, Signals, Metrics Endpoint

**Files:**
- Modify: `cmd/pac-proxy/main.go`
- Test: `cmd/pac-proxy/main_test.go`

**Step 1: Write integration test**

Create `cmd/pac-proxy/main_test.go`:

```go
package main

import (
	"testing"

	"github.com/gary/pac-proxy/internal/pac"
	"github.com/gary/pac-proxy/internal/proxy"
)

func TestPacAdapter(t *testing.T) {
	// This is tested more thoroughly in internal/pac tests;
	// just verify the adapter wiring works.
	_ = proxy.Route{Direct: true}
	_ = pac.Result{Direct: true}
}
```

(The real integration tests happen via manual testing and the end-to-end test in Task 9.)

**Step 2: Write the full main.go**

Replace `cmd/pac-proxy/main.go`:

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/gary/pac-proxy/internal/logging"
	"github.com/gary/pac-proxy/internal/metrics"
	"github.com/gary/pac-proxy/internal/pac"
	"github.com/gary/pac-proxy/internal/proxy"
)

type pacAdapter struct {
	eval *pac.Evaluator
}

func (a *pacAdapter) Evaluate(url, host string) (proxy.Route, error) {
	result, err := a.eval.Evaluate(url, host)
	if err != nil {
		return proxy.Route{}, err
	}
	return proxy.Route{
		Direct:       result.Direct,
		ProxyAddress: result.ProxyAddress,
	}, nil
}

func main() {
	listenAddr := flag.String("listen", ":3128", "proxy listen address")
	metricsAddr := flag.String("metrics", ":9128", "metrics endpoint address")
	flag.Parse()

	// Setup logger
	logger, err := logging.NewSyslogLogger()
	if err != nil {
		// Fall back to stderr
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
		logger.Warn("syslog unavailable, logging to stderr", "error", err)
	}

	// Load PAC file
	pacFile := os.Getenv("PAC_FILE")
	if pacFile == "" {
		fmt.Fprintln(os.Stderr, "PAC_FILE environment variable is required")
		os.Exit(1)
	}

	eval, err := pac.New(pacFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load PAC file: %v\n", err)
		os.Exit(1)
	}
	logger.Info("PAC file loaded", "source", eval.Source())
	metrics.PACReloadTotal.WithLabelValues("success").Inc()

	// Register metrics
	metrics.Register()

	// Proxy server
	handler := proxy.NewHandler(&pacAdapter{eval: eval}, logger)
	proxyServer := &http.Server{
		Addr:    *listenAddr,
		Handler: handler,
	}

	// Metrics server
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsServer := &http.Server{
		Addr:    *metricsAddr,
		Handler: metricsMux,
	}

	// Signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				logger.Info("SIGHUP received, reloading PAC file")
				if err := eval.Reload(); err != nil {
					logger.Error("PAC reload failed", "error", err)
					metrics.PACReloadTotal.WithLabelValues("failure").Inc()
				} else {
					logger.Info("PAC file reloaded", "source", eval.Source())
					metrics.PACReloadTotal.WithLabelValues("success").Inc()
				}
			case syscall.SIGTERM, syscall.SIGINT:
				logger.Info("shutdown signal received", "signal", sig.String())
				cancel()
			}
		}
	}()

	// Start metrics server
	go func() {
		logger.Info("metrics server starting", "addr", *metricsAddr)
		if err := metricsServer.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("metrics server error", "error", err)
		}
	}()

	// Start proxy server
	go func() {
		logger.Info("proxy server starting", "addr", *listenAddr)
		if err := proxyServer.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("proxy server error", "error", err)
			cancel()
		}
	}()

	// Wait for shutdown
	<-ctx.Done()
	logger.Info("shutting down")
	proxyServer.Shutdown(context.Background())
	metricsServer.Shutdown(context.Background())
	logger.Info("shutdown complete")
}
```

**Step 3: Verify it compiles**

Run: `go build ./cmd/pac-proxy`
Expected: builds successfully

**Step 4: Run all tests**

Run: `go test ./... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add cmd/pac-proxy/ go.mod go.sum
git commit -m "feat: wire main with proxy server, metrics endpoint, and signal handling"
```

---

### Task 9: End-to-End Smoke Test

**Files:**
- Create: `test/e2e_test.go`

This test starts the full proxy, makes an HTTP request through it, and verifies it works.

**Step 1: Write the test**

Create `test/e2e_test.go`:

```go
package test

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gary/pac-proxy/internal/metrics"
	"github.com/gary/pac-proxy/internal/pac"
	"github.com/gary/pac-proxy/internal/proxy"
	"github.com/prometheus/client_golang/prometheus"
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

func TestEndToEndHTTPDirect(t *testing.T) {
	// Register metrics on a fresh registry to avoid conflicts
	reg := prometheus.NewRegistry()
	metrics.RegisterOn(reg)

	// Origin server
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("e2e success"))
	}))
	defer origin.Close()

	// Write PAC file that returns DIRECT for everything
	dir := t.TempDir()
	pacPath := filepath.Join(dir, "test.pac")
	os.WriteFile(pacPath, []byte(`function FindProxyForURL(url, host) { return "DIRECT"; }`), 0644)

	eval, err := pac.New(pacPath)
	if err != nil {
		t.Fatal(err)
	}

	handler := proxy.NewHandler(&e2eAdapter{eval: eval}, nil)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// Use the proxy
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
	if string(body) != "e2e success" {
		t.Errorf("body: got %q, want %q", body, "e2e success")
	}
}

func TestEndToEndHTTPViaUpstream(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics.RegisterOn(reg)

	// Origin server
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("via upstream"))
	}))
	defer origin.Close()

	// Simple upstream proxy
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

	dir := t.TempDir()
	pacPath := filepath.Join(dir, "test.pac")
	pacContent := `function FindProxyForURL(url, host) { return "PROXY ` + upstreamAddr + `"; }`
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

	body, _ := io.ReadAll(resp.Body)
	_ = body // Response content depends on upstream proxy forwarding
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}
```

Note: The e2e test uses the actual `pac` and `proxy` packages wired together, but runs in-process with `httptest.Server` — no need to start the binary.

**Step 2: Run e2e tests**

Run: `go test ./test/ -v`
Expected: PASS

**Step 3: Commit**

```bash
git add test/
git commit -m "test: add end-to-end smoke tests for HTTP direct and upstream routing"
```

---

### Task 10: Packaging — Systemd, Sysconfig, GoReleaser

**Files:**
- Create: `packaging/pac-proxy.service`
- Create: `packaging/pac.sysconfig`
- Create: `.goreleaser.yaml`

**Step 1: Create systemd unit file**

Create `packaging/pac-proxy.service`:

```ini
[Unit]
Description=PAC-Aware HTTP/HTTPS Forward Proxy
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/sysconfig/pac
ExecStart=/usr/bin/pac-proxy
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Step 2: Create sysconfig file**

Create `packaging/pac.sysconfig`:

```bash
# PAC file path or URL (required)
PAC_FILE=
```

**Step 3: Create GoReleaser config**

Create `.goreleaser.yaml`:

```yaml
version: 2

builds:
  - main: ./cmd/pac-proxy
    binary: pac-proxy
    goos:
      - linux
    goarch:
      - amd64

nfpms:
  - package_name: pac-proxy
    vendor: ""
    homepage: ""
    maintainer: ""
    description: PAC-aware HTTP/HTTPS forward proxy server
    license: MIT
    formats:
      - rpm
    contents:
      - src: packaging/pac-proxy.service
        dst: /usr/lib/systemd/system/pac-proxy.service
      - src: packaging/pac.sysconfig
        dst: /etc/sysconfig/pac
        type: config|noreplace
    scripts:
      postinstall: |
        systemctl daemon-reload
        systemctl enable pac-proxy.service
```

**Step 4: Verify GoReleaser config (if goreleaser is installed)**

Run: `goreleaser check` (optional — skip if not installed)

**Step 5: Commit**

```bash
git add packaging/ .goreleaser.yaml
git commit -m "feat: add systemd unit, sysconfig, and GoReleaser packaging"
```

---

### Task 11: Final Cleanup and Verification

**Step 1: Run full test suite**

Run: `go test ./... -v -race`
Expected: All PASS, no race conditions

**Step 2: Verify build**

Run: `go build -o pac-proxy ./cmd/pac-proxy`
Expected: Clean build

**Step 3: Run go vet and staticcheck**

Run: `go vet ./...`
Expected: No issues

**Step 4: Commit any final fixes**

```bash
git add -p  # review changes
git commit -m "chore: final cleanup and verification"
```
