# cf-zerotrust

Go package for validating [Cloudflare Zero Trust (Access)](https://developers.cloudflare.com/cloudflare-one/policies/access/) JWT tokens and retrieving authenticated user identities.

## Installation

```bash
go get github.com/potakhov/cf-zerotrust
```

## Usage

### Create a Validator

```go
v, err := zerotrust.New(zerotrust.Config{
    TeamDomain: "myteam",   // myteam.cloudflareaccess.com
    Audience:   "your-aud-tag",
})
```

### HTTP Middleware

Validates the `Cf-Access-Jwt-Assertion` header on every request. On success the authenticated email is stored in the request context; on failure a `403 Forbidden` is returned.

```go
mux := http.NewServeMux()
mux.Handle("/protected", v.Middleware(protectedHandler))
```

Retrieve the email downstream:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    email, err := zerotrust.EmailFromContext(r.Context())
    if err != nil {
        http.Error(w, "unauthenticated", http.StatusUnauthorized)
        return
    }
    fmt.Fprintf(w, "Hello, %s", email)
}
```

### Validate a Token Directly

```go
email, err := v.ValidateToken(tokenStr)
```

### Get Full Identity

Fetches the user's name and email from Cloudflare using the `CF_Authorization` cookie. Results are cached for 1 hour.

```go
identity, err := v.GetIdentity(cfAuthCookieValue, email)
fmt.Println(identity.Name, identity.Email)
```

### Identity from Request (Convenience)

Validates the token and fetches the full identity in one call. Falls back to email-only if the `CF_Authorization` cookie is missing.

```go
identity, err := v.IdentityFromRequest(r)
```

## API Reference

### Types

| Type | Description |
|------|-------------|
| `Config` | Configuration: `TeamDomain` and `Audience` |
| `Identity` | Authenticated user: `Email` and `Name` |
| `Validator` | Stateful validator with key and identity caching |

### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `New` | `New(cfg Config) (*Validator, error)` | Create a new validator |
| `EmailFromContext` | `EmailFromContext(ctx context.Context) (string, error)` | Extract email from request context |

### Validator Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `ValidateToken` | `ValidateToken(tokenStr string) (string, error)` | Validate a JWT and return the email |
| `GetIdentity` | `GetIdentity(cfAuthCookie, email string) (Identity, error)` | Fetch full identity (cached) |
| `IdentityFromRequest` | `IdentityFromRequest(r *http.Request) (Identity, error)` | Validate + fetch identity from an HTTP request |
| `Middleware` | `Middleware(next http.Handler) http.Handler` | HTTP middleware for token validation |

## How It Works

- RSA public keys are fetched from `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` and refreshed every 5 minutes.
- JWTs are validated against the configured audience with expiration checks.
- Identity lookups hit `https://<team>.cloudflareaccess.com/cdn-cgi/access/get-identity` and are cached for 1 hour.
