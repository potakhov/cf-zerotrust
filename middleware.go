package zerotrust

import (
	"context"
	"fmt"
	"net/http"
)

type contextKey string

const contextKeyIdentity contextKey = "cf-identity"

// Middleware returns an HTTP middleware that validates Cloudflare Access JWT
// tokens. On success, it stores the email in the request context (retrievable
// via EmailFromContext). On failure, it responds with 403 Forbidden.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Cf-Access-Jwt-Assertion")
		if tokenStr == "" {
			http.Error(w, `{"error":"missing CF access token"}`, http.StatusForbidden)
			return
		}

		email, err := v.ValidateToken(tokenStr)
		if err != nil {
			http.Error(w, `{"error":"authentication failed"}`, http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), contextKeyIdentity, email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// EmailFromContext extracts the authenticated email from the request context,
// as set by Middleware.
func EmailFromContext(ctx context.Context) (string, error) {
	email, ok := ctx.Value(contextKeyIdentity).(string)
	if !ok {
		return "", fmt.Errorf("no email found in context")
	}
	return email, nil
}
