package zerotrust

// Config holds the Cloudflare Access configuration.
type Config struct {
	TeamDomain string `json:"team_domain"` // e.g. "myteam" for myteam.cloudflareaccess.com
	Audience   string `json:"audience"`    // Application Audience (AUD) tag
}

// Identity represents a Cloudflare Access authenticated user.
type Identity struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}
