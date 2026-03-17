// Package zerotrust provides Cloudflare Zero Trust (Access) JWT validation
// and user identity retrieval.
package zerotrust

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type certsResponse struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Validator validates Cloudflare Access JWT tokens and retrieves user identity.
type Validator struct {
	teamDomain string
	audience   string

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time

	idMu       sync.RWMutex
	idCache    map[string]idCacheEntry
	idCacheTTL time.Duration
}

// New creates a new Validator from the given config.
// Returns an error if required fields are missing.
func New(cfg Config) (*Validator, error) {
	if cfg.TeamDomain == "" {
		return nil, fmt.Errorf("cf-zerotrust: team_domain is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("cf-zerotrust: audience is required")
	}
	return &Validator{
		teamDomain: cfg.TeamDomain,
		audience:   cfg.Audience,
		keys:       make(map[string]*rsa.PublicKey),
		idCache:    make(map[string]idCacheEntry),
		idCacheTTL: 1 * time.Hour,
	}, nil
}

func (v *Validator) certsURL() string {
	return fmt.Sprintf("https://%s.cloudflareaccess.com/cdn-cgi/access/certs", v.teamDomain)
}

// LogoutURL returns the Cloudflare Access logout URL for this team domain.
func (v *Validator) LogoutURL() string {
	return fmt.Sprintf("https://%s.cloudflareaccess.com/cdn-cgi/access/logout", v.teamDomain)
}

// LogoutHandler returns an http.Handler that redirects the user to the
// Cloudflare Access logout endpoint, revoking their session.
func (v *Validator) LogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, v.LogoutURL(), http.StatusFound)
	})
}

func (v *Validator) fetchKeys() error {
	resp, err := http.Get(v.certsURL())
	if err != nil {
		return fmt.Errorf("fetch CF certs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CF certs returned %d", resp.StatusCode)
	}

	var certs certsResponse
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return fmt.Errorf("decode CF certs: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range certs.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pubKey, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pubKey
	}

	v.mu.Lock()
	v.keys = keys
	v.lastFetch = time.Now()
	v.mu.Unlock()

	return nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func (v *Validator) getKeys() (map[string]*rsa.PublicKey, error) {
	v.mu.RLock()
	age := time.Since(v.lastFetch)
	keys := v.keys
	v.mu.RUnlock()

	if age > 5*time.Minute || len(keys) == 0 {
		if err := v.fetchKeys(); err != nil {
			if len(keys) > 0 {
				return keys, nil
			}
			return nil, err
		}
		v.mu.RLock()
		keys = v.keys
		v.mu.RUnlock()
	}
	return keys, nil
}

// ValidateToken validates a Cloudflare Access JWT token string and returns
// the parsed claims. The token is typically found in the
// Cf-Access-Jwt-Assertion header.
func (v *Validator) ValidateToken(tokenStr string) (*Claims, error) {
	keys, err := v.getKeys()
	if err != nil {
		return nil, fmt.Errorf("get CF keys: %w", err)
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		key, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown key ID: %s", kid)
		}
		return key, nil
	}, jwt.WithAudience(v.audience), jwt.WithExpirationRequired())

	if err != nil {
		return nil, fmt.Errorf("validate JWT: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	c := &Claims{
		Email:         claimStr(mapClaims, "email"),
		Subject:       claimStr(mapClaims, "sub"),
		CommonName:    claimStr(mapClaims, "common_name"),
		Country:       claimStr(mapClaims, "country"),
		Type:          claimStr(mapClaims, "type"),
		IdentityNonce: claimStr(mapClaims, "identity_nonce"),
	}

	if iat, ok := mapClaims["iat"].(float64); ok {
		c.IssuedAt = int64(iat)
	}
	if exp, ok := mapClaims["exp"].(float64); ok {
		c.ExpiresAt = int64(exp)
	}

	return c, nil
}

func claimStr(claims jwt.MapClaims, key string) string {
	s, _ := claims[key].(string)
	return s
}
