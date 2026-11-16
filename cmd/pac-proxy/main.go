package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/goodtune/pac-proxy/internal/logging"
	"github.com/goodtune/pac-proxy/internal/metrics"
	"github.com/goodtune/pac-proxy/internal/pac"
	"github.com/goodtune/pac-proxy/internal/proxy"
)

// version is set at build time by GoReleaser via -ldflags.
var version = "dev"

type pacAdapter struct {
	eval *pac.Evaluator
}

func (a *pacAdapter) Evaluate(url string) (proxy.Route, error) {
	result, err := a.eval.Evaluate(url)
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
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	// Setup logger: OTLP when the OTEL_* environment asks for it, else stderr
	logger, shutdownLogging, err := logging.New(context.Background(), version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to set up logging: %v\n", err)
		os.Exit(1)
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

	// Flush buffered log records; bounded so an unreachable collector
	// cannot hold up exit.
	flushCtx, cancelFlush := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFlush()
	if err := shutdownLogging(flushCtx); err != nil {
		fmt.Fprintf(os.Stderr, "flushing logs: %v\n", err)
	}
}
