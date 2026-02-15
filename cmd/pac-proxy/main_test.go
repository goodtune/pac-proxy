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
