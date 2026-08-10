package auth

import "net/http"

// RateLimit wraps the login handler chain.
func RateLimit(next http.Handler) http.Handler {
	return next
}
