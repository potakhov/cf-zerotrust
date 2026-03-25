package zerotrust

import (
	"context"
	"fmt"
	"net/http"
)

type contextKey string

const contextKeyAuth contextKey = "cf-auth"

// Middleware returns an HTTP middleware that validates Cloudflare Access JWT
// tokens (both user and service tokens). On success, it stores an AuthResult
// in the request context. On failure, it responds with 403 Forbidden.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Cf-Access-Jwt-Assertion")
		if tokenStr == "" {
			http.Error(w, `{"error":"missing CF access token"}`, http.StatusForbidden)
			return
		}

		claims, err := v.ValidateToken(tokenStr)
		if err != nil {
			http.Error(w, `{"error":"authentication failed"}`, http.StatusForbidden)
			return
		}

		result := &AuthResult{Claims: *claims}
		ctx := context.WithValue(r.Context(), contextKeyAuth, result)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MiddlewareWithIdentity is like Middleware but also fetches the full identity.
// For service tokens, a synthetic identity is built from JWT claims.
// For user tokens, the identity is fetched via the CF_Authorization cookie
// (falling back to a partial identity from claims if the cookie is missing).
// The identity is available via IdentityFromContext.
func (v *Validator) MiddlewareWithIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, claims, err := v.IdentityFromRequest(r)
		if err != nil {
			http.Error(w, `{"error":"authentication failed"}`, http.StatusForbidden)
			return
		}

		result := &AuthResult{Claims: *claims, Identity: &id}
		ctx := context.WithValue(r.Context(), contextKeyAuth, result)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthResultFromContext extracts the full AuthResult from the request context.
func AuthResultFromContext(ctx context.Context) (*AuthResult, error) {
	result, ok := ctx.Value(contextKeyAuth).(*AuthResult)
	if !ok || result == nil {
		return nil, fmt.Errorf("no auth result found in context")
	}
	return result, nil
}

// ClaimsFromContext extracts the validated Claims from the request context.
func ClaimsFromContext(ctx context.Context) (*Claims, error) {
	result, err := AuthResultFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return &result.Claims, nil
}

// EmailFromContext extracts the authenticated email from the request context.
// For service tokens (which have no email), returns an empty string and nil error.
// Returns an error only if no auth result exists in the context.
func EmailFromContext(ctx context.Context) (string, error) {
	result, err := AuthResultFromContext(ctx)
	if err != nil {
		return "", err
	}
	return result.Claims.Email, nil
}

// PrincipalFromContext returns the identifying string for the authenticated
// entity: email for user tokens, common name for service tokens.
func PrincipalFromContext(ctx context.Context) (string, error) {
	result, err := AuthResultFromContext(ctx)
	if err != nil {
		return "", err
	}
	return result.Principal(), nil
}

// IsServiceTokenFromContext reports whether the request was authenticated
// via a Cloudflare Access service token.
func IsServiceTokenFromContext(ctx context.Context) bool {
	result, _ := AuthResultFromContext(ctx)
	return result != nil && result.IsServiceToken()
}

// IdentityFromContext extracts the Identity from the request context.
// Returns nil if no identity was fetched (e.g., middleware was used without
// WithIdentity option) or no auth result exists.
func IdentityFromContext(ctx context.Context) *Identity {
	result, _ := AuthResultFromContext(ctx)
	if result == nil {
		return nil
	}
	return result.Identity
}
