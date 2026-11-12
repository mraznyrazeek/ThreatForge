
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ThreatForge.Api.Tests.Security;

public sealed class TestAuthenticationHandler
    : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "TestAuthentication";

    // Test-only header. Never register this handler
    // in the production ThreatForge API.
    public const string IdentityHeader =
        "X-ThreatForge-Test-Identity";

    public const string Anonymous = "anonymous";
    public const string NoRole = "no-role";
    public const string Analyst = "analyst";
    public const string Administrator = "administrator";

    public TestAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult>
        HandleAuthenticateAsync()
    {
        // Preserve existing integration-test behavior:
        // requests without the test header are Analysts.
        var identityType = Analyst;

        if (Request.Headers.TryGetValue(
            IdentityHeader,
            out var headerValues))
        {
            identityType = headerValues.ToString();
        }

        if (identityType == Anonymous)
        {
            return Task.FromResult(
                AuthenticateResult.NoResult());
        }

        if (identityType != Analyst &&
            identityType != Administrator &&
            identityType != NoRole)
        {
            return Task.FromResult(
                AuthenticateResult.Fail(
                    "Unsupported test identity."));
        }

        var claims = new List<Claim>
        {
            new(
                ClaimTypes.NameIdentifier,
                $"threatforge-test-{identityType}"),

            new(
                ClaimTypes.Name,
                $"ThreatForge Test {identityType}")
        };

        // The no-role identity is authenticated
        // but has no permitted application role.
        if (identityType != NoRole)
        {
            claims.Add(
                new Claim(
                    ClaimTypes.Role,
                    identityType));
        }

        var identity = new ClaimsIdentity(
            claims,
            SchemeName,
            ClaimTypes.Name,
            ClaimTypes.Role);

        var principal = new ClaimsPrincipal(identity);

        var ticket = new AuthenticationTicket(
            principal,
            SchemeName);

        return Task.FromResult(
            AuthenticateResult.Success(ticket));
    }
}
