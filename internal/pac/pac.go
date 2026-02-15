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
