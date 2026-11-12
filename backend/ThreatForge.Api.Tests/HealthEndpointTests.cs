
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using ThreatForge.Api.Tests.Security;
using Xunit;

namespace ThreatForge.Api.Tests;

public sealed class HealthEndpointTests
    : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public HealthEndpointTests(
        WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task GetHealth_ReturnsHttp200()
    {
        using var response = await _client.GetAsync(
            "/api/v1/health"
        );

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode
        );
    }

    [Fact]
    public async Task GetHealth_ReturnsExpectedMetadata()
    {
        using var response = await _client.GetAsync(
            "/api/v1/health"
        );

        response.EnsureSuccessStatusCode();

        using var payload = await response.Content
            .ReadFromJsonAsync<JsonDocument>();

        Assert.NotNull(payload);

        var root = payload.RootElement;

        Assert.Equal(
            "healthy",
            root.GetProperty("status").GetString()
        );

        Assert.Equal(
            "ThreatForge.Api",
            root.GetProperty("service").GetString()
        );

        Assert.Equal(
            "1.0",
            root.GetProperty("version").GetString()
        );
    }

    [Fact]
    public async Task GetHealth_ReturnsValidUtcTimestamp()
    {
        using var response = await _client.GetAsync(
            "/api/v1/health"
        );

        response.EnsureSuccessStatusCode();

        using var payload = await response.Content
            .ReadFromJsonAsync<JsonDocument>();

        Assert.NotNull(payload);

        var timestamp = payload.RootElement
            .GetProperty("timestampUtc")
            .GetDateTimeOffset();

        Assert.Equal(
            TimeSpan.Zero,
            timestamp.Offset
        );

        Assert.True(
            timestamp <= DateTimeOffset.UtcNow
        );
    }

    [Fact]
    public async Task UnknownEndpoint_Returns404()
    {
        // The production fallback policy protects
        // unmatched routes too.
        //
        // Authenticate as a test Analyst so routing
        // can return the expected 404 response.
        using var authenticatedFactory = _factory
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureTestServices(services =>
                {
                    TestAuthenticationConfiguration
                        .AddTestAuthentication(services);
                });
            });

        using var client = authenticatedFactory.CreateClient();

        using var response = await client.GetAsync(
            "/api/v1/does-not-exist"
        );

        Assert.Equal(
            HttpStatusCode.NotFound,
            response.StatusCode
        );
    }

    [Fact]
    public async Task HealthEndpoint_ReturnsJson()
    {
        using var response = await _client.GetAsync(
            "/api/v1/health"
        );

        Assert.Equal(
            "application/json",
            response.Content.Headers.ContentType?.MediaType
        );
    }
}
