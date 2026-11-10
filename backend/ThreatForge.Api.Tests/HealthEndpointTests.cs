
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace ThreatForge.Api.Tests;

public sealed class HealthEndpointTests
    : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public HealthEndpointTests(
        WebApplicationFactory<Program> factory)
    {
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
        using var response = await _client.GetAsync(
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
