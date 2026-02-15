package pac_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goodtune/pac-proxy/internal/pac"
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
