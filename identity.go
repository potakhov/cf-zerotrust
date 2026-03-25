package zerotrust

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type idCacheEntry struct {
	identity Identity
	fetched  time.Time
}

func (v *Validator) identityURL() string {
	return fmt.Sprintf("https://%s.cloudflareaccess.com/cdn-cgi/access/get-identity", v.teamDomain)
}

// GetIdentity retrieves the full identity for an authenticated user.
// It requires the CF_Authorization cookie value from the request.
// Results are cached by subject (the stable user ID from the JWT) for 1 hour.
func (v *Validator) GetIdentity(cfAuthCookie string, subject string) (Identity, error) {
	if subject != "" {
		v.idMu.RLock()
		if entry, ok := v.idCache[subject]; ok && time.Since(entry.fetched) < v.idCacheTTL {
			v.idMu.RUnlock()
			return entry.identity, nil
		}
		v.idMu.RUnlock()
	}

	id, err := v.fetchIdentity(cfAuthCookie)
	if err != nil {
		return Identity{}, err
	}

	if subject != "" {
		v.idMu.Lock()
		v.idCache[subject] = idCacheEntry{identity: id, fetched: time.Now()}
		v.idMu.Unlock()
	}

	return id, nil
}

func (v *Validator) fetchIdentity(cfAuthCookie string) (Identity, error) {
	req, err := http.NewRequest("GET", v.identityURL(), nil)
	if err != nil {
		return Identity{}, err
	}
	req.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: cfAuthCookie})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("fetch CF identity: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("CF identity returned %d", resp.StatusCode)
	}

	var result Identity
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return Identity{}, fmt.Errorf("decode CF identity: %w", err)
	}
	return result, nil
}

// ServiceTokenIdentityFromClaims builds a synthetic Identity from service token
// JWT claims. Service tokens don't have a user identity endpoint, so the
// identity is derived entirely from the token claims.
func ServiceTokenIdentityFromClaims(claims *Claims) Identity {
	return Identity{
		ServiceToken: true,
		CommonName:   claims.CommonName,
		Country:      claims.Country,
	}
}

// IdentityFromRequest validates the token, then fetches the full identity
// (name, email, groups, etc.) using the CF_Authorization cookie.
// Returns both the identity and the validated JWT claims.
//
// For service tokens (identified by CommonName and no email), a synthetic
// identity is returned from the JWT claims — no cookie or identity endpoint
// is needed.
//
// For user tokens, if the cookie is missing, returns a partial identity with
// just the email from claims.
func (v *Validator) IdentityFromRequest(r *http.Request) (Identity, *Claims, error) {
	tokenStr := r.Header.Get("Cf-Access-Jwt-Assertion")
	if tokenStr == "" {
		return Identity{}, nil, fmt.Errorf("missing Cf-Access-Jwt-Assertion header")
	}

	claims, err := v.ValidateToken(tokenStr)
	if err != nil {
		return Identity{}, nil, err
	}

	if claims.IsServiceToken() {
		return ServiceTokenIdentityFromClaims(claims), claims, nil
	}

	cookie, err := r.Cookie("CF_Authorization")
	if err != nil {
		return Identity{Email: claims.Email}, claims, nil
	}

	id, err := v.GetIdentity(cookie.Value, claims.Subject)
	if err != nil {
		return Identity{Email: claims.Email}, claims, nil
	}

	return id, claims, nil
}
