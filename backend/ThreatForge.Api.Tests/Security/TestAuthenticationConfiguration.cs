
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace ThreatForge.Api.Tests.Security;

public static class TestAuthenticationConfiguration
{
    public static void AddTestAuthentication(
        IServiceCollection services)
    {
        // Override the default authentication scheme
        // for integration tests only.
        services.AddAuthentication(options =>
        {
            options.DefaultScheme =
                TestAuthenticationHandler.SchemeName;

            options.DefaultAuthenticateScheme =
                TestAuthenticationHandler.SchemeName;

            options.DefaultChallengeScheme =
                TestAuthenticationHandler.SchemeName;

            options.DefaultForbidScheme =
                TestAuthenticationHandler.SchemeName;
        })
        .AddScheme<
            AuthenticationSchemeOptions,
            TestAuthenticationHandler>(
                TestAuthenticationHandler.SchemeName,
                options => { });
    }
}
