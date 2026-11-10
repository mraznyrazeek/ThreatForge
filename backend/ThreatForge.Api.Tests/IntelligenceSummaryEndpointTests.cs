
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ThreatForge.Api.Models;
using ThreatForge.Api.Services;
using Xunit;

namespace ThreatForge.Api.Tests;

public sealed class IntelligenceSummaryEndpointTests
{
    private static WebApplicationFactory<Program>
        CreateTestFactory()
    {
        return new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureTestServices(services =>
                {
                    services.RemoveAll<
                        IIntelligenceSummaryService>();

                    services.AddSingleton<
                        IIntelligenceSummaryService,
                        FakeIntelligenceSummaryService>();
                });
            });
    }

    [Fact]
    public async Task GetSummary_ReturnsHttp200()
    {
        using var factory = CreateTestFactory();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync(
            "/api/v1/intelligence/summary");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);
    }

    [Fact]
    public async Task GetSummary_ReturnsExpectedCounts()
    {
        using var factory = CreateTestFactory();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync(
            "/api/v1/intelligence/summary");

        response.EnsureSuccessStatusCode();

        using var payload = await response.Content
            .ReadFromJsonAsync<JsonDocument>();

        Assert.NotNull(payload);

        var root = payload.RootElement;

        Assert.Equal(
            100,
            root.GetProperty(
                "canonicalIndicators").GetInt64());

        Assert.Equal(
            105,
            root.GetProperty(
                "sourceObservations").GetInt64());

        Assert.Equal(
            2,
            root.GetProperty(
                "intelligenceSources").GetInt64());
    }

    [Fact]
    public async Task GetSummary_ReturnsValidUtcTimestamp()
    {
        using var factory = CreateTestFactory();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync(
            "/api/v1/intelligence/summary");

        response.EnsureSuccessStatusCode();

        using var payload = await response.Content
            .ReadFromJsonAsync<JsonDocument>();

        Assert.NotNull(payload);

        var timestamp = payload.RootElement
            .GetProperty("generatedAtUtc")
            .GetDateTimeOffset();

        Assert.Equal(TimeSpan.Zero, timestamp.Offset);

        Assert.True(
            timestamp <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task GetSummary_ReturnsJson()
    {
        using var factory = CreateTestFactory();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync(
            "/api/v1/intelligence/summary");

        Assert.Equal(
            "application/json",
            response.Content.Headers.ContentType?.MediaType);
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
