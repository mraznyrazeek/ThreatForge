
# ThreatForge — Keycloak Authentication and Authorization

**Milestone:** M7.5
**Status:** Implemented and validated for local development
**Identity Provider:** Keycloak 26.8.2
**API Framework:** ASP.NET Core 10
**Authentication:** OpenID Connect / OAuth 2.0
**Authorization:** Role-Based Access Control (RBAC)

---

## 1. Overview

ThreatForge uses Keycloak as its identity provider to authenticate
users and issue signed access tokens.

The ASP.NET Core API validates Keycloak-issued JWT access tokens
before granting access to protected threat-intelligence endpoints.

The implementation separates:

- Authentication: Verifying the caller's identity through JWT validation.
- Authorization: Determining whether an authenticated caller has
  a permitted ThreatForge application role.

The current implementation supports two API roles:

- `analyst`
- `administrator`

This milestone establishes the authentication and authorization
foundation for future frontend integration.

---

## 2. Authentication Architecture

The local authentication flow is:

1. A client initiates an OpenID Connect authorization request.
2. Keycloak authenticates the user.
3. Keycloak returns an authorization code to the registered callback.
4. The client exchanges the code using PKCE S256.
5. Keycloak issues a JWT access token.
6. The client sends the token to ThreatForge using the
   `Authorization: Bearer <token>` header.
7. ASP.NET Core validates the token.
8. ThreatForge evaluates application roles and allows or denies access.

### Local components

| Component | Address |
|---|---|
| Keycloak | `http://localhost:8080` |
| ThreatForge API | `http://127.0.0.1:5050` |
| PKCE callback | `http://localhost:5173/` |

These addresses are intended for local development.

---

## 3. Keycloak Configuration

### Realm

Realm name:

`threatforge`

Issuer:

`http://localhost:8080/realms/threatforge`

### API client

Client ID:

`threatforge-api`

Purpose:

- Represents the protected ThreatForge API.
- Defines API application roles.
- Provides the audience expected during JWT validation.

Configured application roles:

- `analyst`
- `administrator`

### Frontend client

Client ID:

`threatforge-frontend`

Configuration:

- OpenID Connect client
- Public client
- Client authentication disabled
- Standard authorization code flow enabled
- PKCE required
- PKCE method: S256
- Direct access grants disabled
- Implicit flow disabled

Registered redirect URI:

`http://localhost:5173/`

### Audience mapper

Dedicated client scope:

`threatforge-frontend-dedicated`

Mapper:

`threatforge-api-audience`

Mapper type:

`Audience`

Included client audience:

`threatforge-api`

The mapper adds the required API audience to access tokens.

The existing local test account is assigned the API's
`analyst` role.

No account passwords or tokens are stored in this document.

---

## 4. JWT Validation

The ASP.NET Core API uses JWT Bearer authentication.

Relevant configuration:

```csharp
options.Authority = jwtAuthority;
options.Audience = jwtAudience;

options.TokenValidationParameters =
    new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = jwtAuthority.TrimEnd('/'),

        ValidateAudience = true,
        ValidAudience = jwtAudience,

        ValidateLifetime = true,
        RequireExpirationTime = true,

        ValidateIssuerSigningKey = true,
        RequireSignedTokens = true,

        ClockSkew = TimeSpan.FromSeconds(30),

        RoleClaimType = ClaimTypes.Role
    };
```

JWT validation verifies:

- Token issuer
- Required API audience
- Token lifetime
- Presence of an expiration timestamp
- Digital signature and signing key
- Application role authorization

The identity provider's signing keys are obtained through
the configured OpenID Connect metadata and JWKS endpoints.

HTTP metadata is permitted only in the Development environment.
Non-development environments require HTTPS for identity-provider
metadata.

---

## 5. Keycloak Role Transformation

Keycloak supplies client roles through the token's
`resource_access` claim.

ThreatForge implements:

`backend/ThreatForge.Api/Security/KeycloakRoleClaimsTransformation.cs`

The transformation extracts roles belonging to:

`threatforge-api`

Only the following recognized application roles are mapped
to ASP.NET Core role claims:

- `analyst`
- `administrator`

Roles associated with unrelated clients are not accepted
as ThreatForge API roles.

The transformation does not replace JWT signature validation.

---

## 6. Authorization Policy

ThreatForge requires authenticated users with an authorized
application role for protected endpoints.

Permitted roles:

- `analyst`
- `administrator`

The API uses a fallback authorization policy to protect
endpoints unless anonymous access is explicitly permitted.

### Public endpoints

`GET /api/v1/health`

This endpoint uses `[AllowAnonymous]` and is accessible
without a bearer token.

### Protected endpoints

- `GET /api/v1/health/database`
- `GET /api/v1/intelligence/summary`
- `GET /api/v1/intelligence/indicators`
- `GET /api/v1/analytics/indicators/distribution`
- `GET /api/v1/analytics/malware/families`
- `GET /api/v1/analytics/temporal/daily`
- `GET /api/v1/analytics/correlation/sources`

Access requires an authenticated caller with an
authorized API role.

The OpenAPI endpoint is allowed anonymously only in
the Development environment.

### HTTP response behavior

| Scenario | Expected HTTP status |
|---|---|
| Public health request | 200 |
| Anonymous request to protected endpoint | 401 |
| Authenticated caller without authorized role | 403 |
| Authorized Analyst | 200 |
| Authorized Administrator | 200 |
| Invalid bearer token | 401 |
| Expired bearer token | 401 |

A fallback authorization policy can also challenge
anonymous requests to unknown routes.

---

## 7. Automated Testing

The .NET integration tests use a test-only authentication
handler rather than obtaining live Keycloak tokens.

Test infrastructure:

- `TestAuthenticationHandler.cs`
- `TestAuthenticationConfiguration.cs`
- `AuthorizationEndpointTests.cs`

Location:

`backend/ThreatForge.Api.Tests/Security/`

The test handler supports:

- Anonymous identity
- Authenticated identity without an application role
- Analyst identity
- Administrator identity
- Unsupported test identity

The test identity selection header is recognized only
by the test authentication handler.

It must never be registered as a production
authentication mechanism.

### Automated test results

Command:

```bash
dotnet test ThreatForge.sln
```

Validated result:

- Total: 51
- Passed: 51
- Failed: 0
- Skipped: 0

These include:

- 45 original API integration tests
- 6 dedicated authorization tests

---

## 8. Live Keycloak JWT Validation

A local Python smoke-test script validates the real
browser-based authentication flow.

Script:

`scripts/security/keycloak_pkce_smoke.py`

The script uses:

- Authorization Code flow
- PKCE S256
- A temporary localhost callback listener
- A real Keycloak-issued JWT
- A protected ThreatForge API endpoint

The script does not print or persist passwords,
authorization codes, or access tokens.

### Verified results

| Check | Result |
|---|---|
| Browser-based Keycloak login | Passed |
| Authorization callback | Passed |
| PKCE token exchange | Passed |
| Expected issuer claim | Passed |
| Required API audience claim | Passed |
| Analyst role claim | Passed |
| Valid JWT accepted by API | HTTP 200 |
| Expired JWT rejected by API | HTTP 401 |
| Malformed JWT rejected by API | HTTP 401 |

The expired-token test reused the original valid token
after its expiration and the API's configured clock
tolerance had elapsed.

### Token lifetime

Keycloak access-token lifespan:

5 minutes

ASP.NET Core clock tolerance:

30 seconds

The existing local expiration test confirmed that the
same token was rejected after its lifetime elapsed.

---

## 9. Local Development Operations

### Start Keycloak

From the repository root:

```bash
docker compose \
  --env-file infrastructure/docker/.env.keycloak \
  -f infrastructure/docker/compose.keycloak.yml \
  up -d
```

### Verify Keycloak

```bash
curl --noproxy '*' -s -o /dev/null \
  -w "%{http_code}\n" \
  http://localhost:8080/realms/threatforge/.well-known/openid-configuration
```

Expected:

`200`

### Start the ASP.NET Core API

```bash
dotnet run \
  --project backend/ThreatForge.Api \
  --urls "http://127.0.0.1:5050"
```

Port 5050 is used because macOS AirPlay Receiver may
occupy port 5000.

### Verify public API access

```bash
curl --noproxy '*' -i \
  http://127.0.0.1:5050/api/v1/health
```

Expected:

`200 OK`

### Verify protected API access without a token

```bash
curl --noproxy '*' -i \
  http://127.0.0.1:5050/api/v1/intelligence/summary
```

Expected:

`401 Unauthorized`

### Run the PKCE smoke test

With Keycloak and the API running:

```bash
python scripts/security/keycloak_pkce_smoke.py
```

The test opens the Keycloak login page and validates
the resulting access token.

The script also checks expiration by retaining the
original token in memory until it expires.

---

## 10. Security Limitations and Future Hardening

M7.5 establishes a working local authentication and
authorization implementation.

It does not establish complete production security readiness.

### Deferred audience-isolation test

The API is configured with:

`ValidateAudience = true`

However, a correctly signed Keycloak token with an
incorrect API audience has not yet been independently
tested against the live API.

During investigation, a temporary Keycloak client
unexpectedly received the `threatforge-api` audience.

This was consistent with audience resolution through
Keycloak client role mappings.

The temporary client was subsequently removed.

Future security testing should:

1. Review effective Keycloak audience mappers.
2. Verify audience isolation between clients.
3. Obtain a valid Keycloak-signed token without
   the `threatforge-api` audience.
4. Confirm that the API rejects it with HTTP 401.

### Additional production considerations

Future security-hardening work should include:

- HTTPS for externally exposed services
- Secure Keycloak deployment configuration
- Production secret management
- Appropriate CORS and redirect-URI restrictions
- Token and session lifecycle testing
- Audit logging
- Expanded authorization-policy coverage
- Deployment-specific threat modeling

---

## 11. Milestone Outcome

ThreatForge M7.5 implements:

- Keycloak identity-provider integration
- Authorization Code + PKCE S256
- JWT Bearer authentication
- API audience validation configuration
- Client-role claim transformation
- Role-based API authorization
- Public and protected endpoint separation
- Automated authentication and authorization tests
- Live Keycloak JWT acceptance and expiration testing

**Conclusion:**

M7.5 authentication and authorization are implemented
and validated for local development.

Production hardening and additional audience-isolation
testing remain future security tasks.
