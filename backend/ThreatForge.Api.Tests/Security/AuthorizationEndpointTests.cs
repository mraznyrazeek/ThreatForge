
using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ThreatForge.Api.Models;
using ThreatForge.Api.Services;
using Xunit;

namespace ThreatForge.Api.Tests.Security;

public sealed class AuthorizationEndpointTests
{
    private const string ProtectedEndpoint =
        "/api/v1/intelligence/summary";

    private const string PublicEndpoint =
        "/api/v1/health";

    private static WebApplicationFactory<Program>
        CreateTestFactory()
    {
        return new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureTestServices(services =>
                {
                    // Replace Keycloak authentication with
                    // a configurable test-only handler.
                    TestAuthenticationConfiguration
                        .AddTestAuthentication(services);

                    // Prevent database access during
                    // successful authorization tests.
                    services.RemoveAll<
                        IIntelligenceSummaryService>();

                    services.AddSingleton<
                        IIntelligenceSummaryService,
                        FakeIntelligenceSummaryService>();
                });
            });
    }

    [Fact]
    public async Task AnonymousUser_ProtectedEndpoint_Returns401()
    {
        using var factory = CreateTestFactory();
        using var client = factory.CreateClient();

        client.DefaultRequestHeaders.Add(
            TestAuthenticationHandler.IdentityHeader,
            TestAuthenticationHandler.Anonymous);

        using var response = await client.GetAsync(
            ProtectedEndpoint);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task AuthenticatedUserWithoutRole_Returns403()
    {
        using var factory = CreateTestFactory();
        using var client = factory.CreateClient();

        client.DefaultRequestHeaders.Add(
            TestAuthenticationHandler.IdentityHeader,
            TestAuthenticationHandler.NoRole);

        using var response = await client.GetAsync(
            ProtectedEndpoint);

        Assert.Equal(
            HttpStatusCode.Forbidden,
            response.StatusCode);
    }

    [Fact]
    public async Task Analyst_ProtectedEndpoint_Returns200()
    {
        using var factory = CreateTestFactory();
        using var client = factory.CreateClient();

        client.DefaultRequestHeaders.Add(
            TestAuthenticationHandler.IdentityHeader,
            TestAuthenticationHandler.Analyst);

        using var response = await client.GetAsync(
            ProtectedEndpoint);

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);
    }

    [Fact]
    public async Task Administrator_ProtectedEndpoint_Returns200()
    {
        using var factory = CreateTestFactory();
        using var client = factory.CreateClient();

        client.DefaultRequestHeaders.Add(
            TestAuthenticationHandler.IdentityHeader,
            TestAuthenticationHandler.Administrator);

        using var response = await client.GetAsync(
            ProtectedEndpoint);

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);
    }

    [Fact]
    public async Task AnonymousUser_PublicHealthEndpoint_Returns200()
    {
        using var factory = CreateTestFactory();
        using var client = factory.CreateClient();

        client.DefaultRequestHeaders.Add(
            TestAuthenticationHandler.IdentityHeader,
            TestAuthenticationHandler.Anonymous);

        using var response = await client.GetAsync(
            PublicEndpoint);

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);
    }

    [Fact]
    public async Task UnknownTestIdentity_ProtectedEndpoint_Returns401()
    {
        using var factory = CreateTestFactory();
        using var client = factory.CreateClient();

        client.DefaultRequestHeaders.Add(
            TestAuthenticationHandler.IdentityHeader,
            "unsupported-role");

        using var response = await client.GetAsync(
            ProtectedEndpoint);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    private sealed class FakeIntelligenceSummaryService
        : IIntelligenceSummaryService
    {
        public Task<IntelligenceSummaryResponse>
            GetSummaryAsync(
                CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new IntelligenceSummaryResponse
                {
                    CanonicalIndicators = 100,
                    SourceObservations = 105,
                    IntelligenceSources = 2,
                    GeneratedAtUtc = DateTimeOffset.UtcNow
                });
        }
    }
}
