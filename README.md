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

Validates the token and fetches the full identity in one call. Returns both the `Identity` and validated `Claims`. For service tokens, a synthetic identity is built from the JWT claims. For user tokens, falls back to email-only identity if the `CF_Authorization` cookie is missing.

```go
identity, claims, err := v.IdentityFromRequest(r)
if identity.IsServiceToken() {
    fmt.Println("Service:", identity.CommonName)
} else {
    fmt.Println("User:", identity.Name, identity.Email)
}
```

## Service Tokens

Cloudflare Access [service tokens](https://developers.cloudflare.com/cloudflare-one/identity/service-tokens/) enable machine-to-machine authentication. Unlike user tokens (which come from a browser login), service tokens authenticate using a **Client ID** and **Client Secret** sent as HTTP headers.

### Differentiating Users from Service Tokens

```go
claims, _ := zerotrust.ClaimsFromContext(r.Context())

if claims.IsServiceToken() {
    // Service token — claims.CommonName contains the Client ID
    fmt.Println("Service:", claims.CommonName)
} else {
    // User login — claims.Email contains the user's email
    fmt.Println("User:", claims.Email)
}
```

Or use the context helpers:

```go
// Returns email for users, Client ID for service tokens
principal, _ := zerotrust.PrincipalFromContext(r.Context())

// Boolean check
if zerotrust.IsServiceTokenFromContext(r.Context()) {
    // handle service token request
}
```

### Middleware with Identity

The standard `Middleware` validates the JWT and stores `Claims` in the context. If you also need the full `Identity` (groups, name, device posture, etc. for users), use `MiddlewareWithIdentity`:

```go
mux.Handle("/api/", v.MiddlewareWithIdentity(apiHandler))
```

For **user tokens**, this fetches the rich identity from Cloudflare's identity endpoint using the `CF_Authorization` cookie (name, groups, IdP info, device posture, etc.).

For **service tokens**, there is no identity endpoint — a synthetic `Identity` is built from the JWT claims with `ServiceToken: true` and `CommonName` populated.

```go
func handler(w http.ResponseWriter, r *http.Request) {
    id := zerotrust.IdentityFromContext(r.Context())
    if id == nil {
        // MiddlewareWithIdentity was not used
        return
    }

    if id.IsServiceToken() {
        fmt.Println("Service token:", id.CommonName)
    } else {
        fmt.Println("User:", id.Name, id.Email)
        for _, g := range id.Groups {
            fmt.Println("  Group:", g.Name)
        }
    }
}
```

### Identity Fields by Token Type

| Field | User Token | Service Token |
|-------|-----------|---------------|
| `Email` | User's email | Empty |
| `Name` | User's display name | Empty |
| `CommonName` | Empty | Client ID (e.g. `3f170a...a0.access`) |
| `ServiceToken` | `false` | `true` |
| `Groups` | Group memberships | Empty |
| `UserUUID` | Stable user ID | Empty |
| `IP`, `Country`, `Geo` | Present | Empty |
| `IsWarp`, `IsGateway` | Present | `false` |
| `DevicePosture` | Present | Empty |

## API Reference

### Types

| Type | Description |
|------|-------------|
| `Config` | Configuration: `TeamDomain` and `Audience` |
| `Claims` | Validated JWT claims: `Email`, `Subject`, `CommonName`, `Country`, `Type`, etc. |
| `Identity` | Full identity: `Email`, `Name`, `Groups`, etc. for users; `CommonName`, `ServiceToken` for service tokens |
| `AuthResult` | Middleware result stored in context, wrapping `Claims` and optionally `Identity` |
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
| `IdentityFromContext` | `IdentityFromContext(ctx) *Identity` | Extract identity from context (requires `MiddlewareWithIdentity`) |
| `ServiceTokenIdentityFromClaims` | `ServiceTokenIdentityFromClaims(claims *Claims) Identity` | Build a synthetic identity from service token claims |

### Validator Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `ValidateToken` | `ValidateToken(tokenStr string) (*Claims, error)` | Validate a JWT and return parsed claims |
| `GetIdentity` | `GetIdentity(cfAuthCookie, subject string) (Identity, error)` | Fetch full identity (cached by subject) |
| `IdentityFromRequest` | `IdentityFromRequest(r *http.Request) (Identity, *Claims, error)` | Validate + fetch identity from an HTTP request |
| `Middleware` | `Middleware(next http.Handler) http.Handler` | HTTP middleware for token validation |
| `MiddlewareWithIdentity` | `MiddlewareWithIdentity(next http.Handler) http.Handler` | Middleware that also fetches/synthesizes identity |
| `LogoutURL` | `LogoutURL() string` | Return the Cloudflare Access logout URL |
| `LogoutHandler` | `LogoutHandler() http.Handler` | HTTP handler that redirects to logout |

## How It Works

- RSA public keys are fetched from `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` and refreshed every 5 minutes.
- JWTs are validated against the configured audience with expiration checks.
- Identity lookups hit `https://<team>.cloudflareaccess.com/cdn-cgi/access/get-identity` and are cached for 1 hour.
