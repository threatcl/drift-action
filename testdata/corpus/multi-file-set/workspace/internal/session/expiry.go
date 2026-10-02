package session

import (
	"net/http"
	"time"
)

// Expiry records activity on the request's session.
func Expiry(store Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s, ok := store.FromRequest(r); ok {
			s.LastSeen = time.Now()
			store.Save(s)
		}
		next.ServeHTTP(w, r)
	})
}
