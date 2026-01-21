package middleware

import (
	"net/http"
	"strings"
)

// HTTPSRedirect creates a middleware that redirects HTTP to HTTPS
func HTTPSRedirect(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Build HTTPS URL
		host := r.Host

		// Remove port from host if present
		if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
			host = host[:colonIndex]
		}

		// Add HTTPS port if not default
		if httpsPort != "443" && httpsPort != "" {
			host = host + ":" + httpsPort
		}

		target := "https://" + host + r.RequestURI

		// 301 permanent redirect
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}
