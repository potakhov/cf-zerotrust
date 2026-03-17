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
// Results are cached for 1 hour.
func (v *Validator) GetIdentity(cfAuthCookie string, email string) (Identity, error) {
	if email != "" {
		v.idMu.RLock()
		if entry, ok := v.idCache[email]; ok && time.Since(entry.fetched) < v.idCacheTTL {
			v.idMu.RUnlock()
			return entry.identity, nil
		}
		v.idMu.RUnlock()
	}

	id, err := v.fetchIdentity(cfAuthCookie)
	if err != nil {
		return Identity{}, err
	}

	if id.Email != "" {
		v.idMu.Lock()
		v.idCache[id.Email] = idCacheEntry{identity: id, fetched: time.Now()}
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

// IdentityFromRequest is a convenience that validates the token, then
// fetches the full identity (name + email) using the CF_Authorization cookie.
// Returns the identity or an error if validation or identity fetch fails.
func (v *Validator) IdentityFromRequest(r *http.Request) (Identity, error) {
	tokenStr := r.Header.Get("Cf-Access-Jwt-Assertion")
	if tokenStr == "" {
		return Identity{}, fmt.Errorf("missing Cf-Access-Jwt-Assertion header")
	}

	email, err := v.ValidateToken(tokenStr)
	if err != nil {
		return Identity{}, err
	}

	cookie, err := r.Cookie("CF_Authorization")
	if err != nil {
		return Identity{Email: email}, nil
	}

	return v.GetIdentity(cookie.Value, email)
}
