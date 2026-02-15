package proxy

import "net/http"

// handleTunnel handles CONNECT requests. Stub — implemented in Task 6.
func (h *Handler) handleTunnel(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "CONNECT not yet implemented", http.StatusNotImplemented)
}
