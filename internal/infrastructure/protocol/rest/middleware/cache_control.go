package middleware

import (
	"net/http"
)

// NoCacheHeader sets 'cache-control' header to 'no-cache' to prevent storing responses in CDN and serve outdated data.
func NoCacheHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}
