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

Validates the `Cf-Access-Jwt-Assertion` header on every request. On success an `AuthResult` (containing the validated `Claims`) is stored in the request context; on failure a `403 Forbidden` is returned.

```go
mux := http.NewServeMux()
mux.Handle("/protected", v.Middleware(protectedHandler))
```

Retrieve auth info downstream:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Get the principal (email for users, common name for service tokens)
    principal, err := zerotrust.PrincipalFromContext(r.Context())
    if err != nil {
        http.Error(w, "unauthenticated", http.StatusUnauthorized)
        return
    }
    fmt.Fprintf(w, "Hello, %s", principal)
}
```

Other context helpers:

```go
// Full auth result with all claims
auth, err := zerotrust.AuthResultFromContext(ctx)

// Just the validated claims
claims, err := zerotrust.ClaimsFromContext(ctx)

// Just the email (empty string for service tokens)
email, err := zerotrust.EmailFromContext(ctx)

// Check if this is a service token
if zerotrust.IsServiceTokenFromContext(ctx) { ... }
```

### Validate a Token Directly

```go
claims, err := v.ValidateToken(tokenStr)
fmt.Println(claims.Email, claims.Subject)
```

### Get Full Identity

Fetches the user's name and email from Cloudflare using the `CF_Authorization` cookie. Results are cached by the JWT subject (stable user ID) for 1 hour.

```go
identity, err := v.GetIdentity(cfAuthCookieValue, claims.Subject)
fmt.Println(identity.Name, identity.Email)
```

### Identity from Request (Convenience)

Validates the token and fetches the full identity in one call. Returns both the `Identity` and validated `Claims`. Falls back to email-only identity if the `CF_Authorization` cookie is missing.

```go
identity, claims, err := v.IdentityFromRequest(r)
fmt.Println(identity.Name, identity.Email, claims.Subject)
```

## API Reference

### Types

| Type | Description |
|------|-------------|
| `Config` | Configuration: `TeamDomain` and `Audience` |
| `Claims` | Validated JWT claims: `Email`, `Subject`, `CommonName`, `Country`, `Type`, etc. |
| `Identity` | Full user identity from Cloudflare: `Email`, `Name`, `UserUUID`, `Groups`, `IP`, etc. |
| `AuthResult` | Middleware result stored in context, wrapping `Claims` |
| `Validator` | Stateful validator with key and identity caching |

### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `New` | `New(cfg Config) (*Validator, error)` | Create a new validator |
| `AuthResultFromContext` | `AuthResultFromContext(ctx) (*AuthResult, error)` | Extract full auth result from context |
| `ClaimsFromContext` | `ClaimsFromContext(ctx) (*Claims, error)` | Extract validated claims from context |
| `EmailFromContext` | `EmailFromContext(ctx) (string, error)` | Extract email from context |
| `PrincipalFromContext` | `PrincipalFromContext(ctx) (string, error)` | Extract principal (email or common name) from context |
| `IsServiceTokenFromContext` | `IsServiceTokenFromContext(ctx) bool` | Check if request used a service token |

### Validator Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `ValidateToken` | `ValidateToken(tokenStr string) (*Claims, error)` | Validate a JWT and return parsed claims |
| `GetIdentity` | `GetIdentity(cfAuthCookie, subject string) (Identity, error)` | Fetch full identity (cached by subject) |
| `IdentityFromRequest` | `IdentityFromRequest(r *http.Request) (Identity, *Claims, error)` | Validate + fetch identity from an HTTP request |
| `Middleware` | `Middleware(next http.Handler) http.Handler` | HTTP middleware for token validation |
| `LogoutURL` | `LogoutURL() string` | Return the Cloudflare Access logout URL |
| `LogoutHandler` | `LogoutHandler() http.Handler` | HTTP handler that redirects to logout |

## How It Works

- RSA public keys are fetched from `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` and refreshed every 5 minutes.
- JWTs are validated against the configured audience with expiration checks.
- Identity lookups hit `https://<team>.cloudflareaccess.com/cdn-cgi/access/get-identity` and are cached for 1 hour.
