package zerotrust

// Config holds the Cloudflare Access configuration.
type Config struct {
	TeamDomain string `json:"team_domain"` // e.g. "myteam" for myteam.cloudflareaccess.com
	Audience   string `json:"audience"`    // Application Audience (AUD) tag
}

// Group represents a Cloudflare Access group membership from the identity provider.
type Group struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// IdPInfo describes the identity provider used for authentication.
type IdPInfo struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// DeviceSession holds per-account device session info.
type DeviceSession struct {
	LastAuthenticated float64 `json:"last_authenticated"`
}

// Identity represents a Cloudflare Access authenticated entity (user or service token),
// as returned by the /cdn-cgi/access/get-identity endpoint or synthesized from JWT claims.
type Identity struct {
	Email          string                   `json:"email"`
	Name           string                   `json:"name"`
	UserUUID       string                   `json:"user_uuid"`
	AccountID      string                   `json:"account_id"`
	Groups         []Group                  `json:"groups"`
	IdP            IdPInfo                  `json:"idp"`
	IP             string                   `json:"ip"`
	Country        string                   `json:"country"`
	Geo            map[string]string        `json:"geo"`
	AuthStatus     string                   `json:"auth_status"`
	IsWarp         bool                     `json:"is_warp"`
	IsGateway      bool                     `json:"is_gateway"`
	DeviceID       string                   `json:"device_id"`
	DevicePosture  map[string]any           `json:"devicePosture"`
	DeviceSessions map[string]DeviceSession `json:"deviceSessions"`
	OIDCFields     map[string]any           `json:"oidc_fields"`
	SAMLAttributes map[string]any           `json:"custom_attributes"`

	// Service token fields — populated when the request is from a service token.
	ServiceToken bool   `json:"service_token"`
	CommonName   string `json:"common_name,omitempty"`
}

// IsServiceToken reports whether this identity represents a service token.
func (id *Identity) IsServiceToken() bool {
	return id.ServiceToken
}

// Principal returns the identifying string: Email for users, CommonName for service tokens.
func (id *Identity) Principal() string {
	if id.Email != "" {
		return id.Email
	}
	return id.CommonName
}

// Claims holds the validated JWT claims from a Cloudflare Access token.
type Claims struct {
	Email         string `json:"email"`
	Subject       string `json:"sub"`           // stable user ID
	CommonName    string `json:"common_name"`   // populated for service tokens
	Country       string `json:"country"`       // country of authentication
	Type          string `json:"type"`          // "app" or "org"
	IdentityNonce string `json:"identity_nonce"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
}

// IsServiceToken reports whether these claims are from a service token
// (no email, identified by CommonName).
func (c *Claims) IsServiceToken() bool {
	return c.Email == "" && c.CommonName != ""
}

// Principal returns the identifying string: Email for user tokens,
// CommonName for service tokens.
func (c *Claims) Principal() string {
	if c.Email != "" {
		return c.Email
	}
	return c.CommonName
}

// AuthResult is the authentication result stored in the request context by Middleware.
type AuthResult struct {
	Claims   Claims
	Identity *Identity // nil unless identity was fetched or synthesized
}

// Principal returns the identifying string for the authenticated entity.
func (a *AuthResult) Principal() string {
	return a.Claims.Principal()
}

// IsServiceToken reports whether this request was authenticated via a service token.
func (a *AuthResult) IsServiceToken() bool {
	return a.Claims.IsServiceToken()
}
