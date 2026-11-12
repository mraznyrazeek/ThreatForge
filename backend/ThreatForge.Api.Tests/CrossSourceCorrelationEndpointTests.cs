
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ThreatForge.Api.Models;
using ThreatForge.Api.Services;
using ThreatForge.Api.Tests.Security;
using Xunit;

namespace ThreatForge.Api.Tests;

public sealed class CrossSourceCorrelationEndpointTests
{
    private const string Endpoint =
        "/api/v1/analytics/correlation/sources";

    private static (
        WebApplicationFactory<Program> Factory,
        FakeCorrelationService Service
    ) CreateFactory()
    {
        var service = new FakeCorrelationService();

        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureTestServices(services =>
                {
                    // Authenticate integration test requests
                    // using the test-only Analyst identity.
                    // Production continues to use Keycloak JWTs.
                    TestAuthenticationConfiguration
                        .AddTestAuthentication(services);

                    // Replace the PostgreSQL-backed correlation
                    // service with deterministic test data.
                    services.RemoveAll<
                        ICrossSourceCorrelationService>();

                    services.AddSingleton<
                        ICrossSourceCorrelationService>(service);
                });
            });

        return (factory, service);
    }

    [Fact]
    public async Task GetCorrelation_ReturnsHttp200()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            using var response =
                await client.GetAsync(Endpoint);

            Assert.Equal(
                HttpStatusCode.OK,
                response.StatusCode);
        }
    }

    [Fact]
    public async Task GetCorrelation_ReturnsExpectedOverlap()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result = await client.GetFromJsonAsync<
                CrossSourceCorrelationResponse>(Endpoint);

            Assert.NotNull(result);

            Assert.Equal(
                2,
                result.SharedCanonicalIndicators);

            var pair = Assert.Single(result.SourcePairs);

            Assert.Equal("ThreatFox", pair.FirstSource);
            Assert.Equal("URLhaus", pair.SecondSource);
            Assert.Equal(2, pair.SharedIndicators);
        }
    }

    [Fact]
    public async Task GetCorrelation_ReturnsValidJsonAndUtcTimestamp()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            using var response =
                await client.GetAsync(Endpoint);

            Assert.Equal(
                "application/json",
                response.Content.Headers.ContentType?.MediaType);

            var result = await response.Content
                .ReadFromJsonAsync<CrossSourceCorrelationResponse>();

            Assert.NotNull(result);

            Assert.Equal(
                TimeSpan.Zero,
                result.GeneratedAtUtc.Offset);

            Assert.True(
                result.GeneratedAtUtc <= DateTimeOffset.UtcNow);
        }
    }

    [Fact]
    public async Task GetCorrelation_NoOverlap_ReturnsEmptyPairs()
    {
        var (factory, service) = CreateFactory();

        service.ReturnEmpty = true;

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result = await client.GetFromJsonAsync<
                CrossSourceCorrelationResponse>(Endpoint);

            Assert.NotNull(result);

            Assert.Equal(
                0,
                result.SharedCanonicalIndicators);

            Assert.Empty(result.SourcePairs);
        }
    }

    [Fact]
    public async Task GetCorrelation_MultiplePairs_ArePreserved()
    {
        var (factory, service) = CreateFactory();

        service.ReturnMultiplePairs = true;

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result = await client.GetFromJsonAsync<
                CrossSourceCorrelationResponse>(Endpoint);

            Assert.NotNull(result);

            Assert.Equal(
                3,
                result.SharedCanonicalIndicators);

            Assert.Equal(3, result.SourcePairs.Count);

            // A canonical indicator may appear in
            // more than one source pair.
            Assert.Equal(
                5,
                result.SourcePairs.Sum(
                    pair => pair.SharedIndicators));

            Assert.True(
                result.SourcePairs.Sum(
                    pair => pair.SharedIndicators)
                > result.SharedCanonicalIndicators);
        }
    }

    [Fact]
    public async Task GetCorrelation_CallsServiceOnce()
    {
        var (factory, service) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            using var response =
                await client.GetAsync(Endpoint);

            Assert.Equal(
                HttpStatusCode.OK,
                response.StatusCode);

            Assert.Equal(1, service.CallCount);
        }
    }

    private sealed class FakeCorrelationService
        : ICrossSourceCorrelationService
    {
        public int CallCount { get; private set; }

        public bool ReturnEmpty { get; set; }

        public bool ReturnMultiplePairs { get; set; }

        public Task<CrossSourceCorrelationResponse>
            GetCorrelationAsync(
                CancellationToken cancellationToken = default)
        {
            CallCount++;

            if (ReturnEmpty)
            {
                return Task.FromResult(
                    new CrossSourceCorrelationResponse
                    {
                        SharedCanonicalIndicators = 0,
                        SourcePairs = [],
                        GeneratedAtUtc = DateTimeOffset.UtcNow
                    });
            }

            if (ReturnMultiplePairs)
            {
                return Task.FromResult(
                    new CrossSourceCorrelationResponse
                    {
                        SharedCanonicalIndicators = 3,
                        SourcePairs =
                        [
                            new SourceOverlapItem
                            {
                                FirstSource = "SourceA",
                                SecondSource = "SourceB",
                                SharedIndicators = 2
                            },
                            new SourceOverlapItem
                            {
                                FirstSource = "SourceA",
                                SecondSource = "SourceC",
                                SharedIndicators = 2
                            },
                            new SourceOverlapItem
                            {
                                FirstSource = "SourceB",
                                SecondSource = "SourceC",
                                SharedIndicators = 1
                            }
                        ],
                        GeneratedAtUtc = DateTimeOffset.UtcNow
                    });
            }

            return Task.FromResult(
                new CrossSourceCorrelationResponse
                {
                    SharedCanonicalIndicators = 2,
                    SourcePairs =
                    [
                        new SourceOverlapItem
                        {
                            FirstSource = "ThreatFox",
                            SecondSource = "URLhaus",
                            SharedIndicators = 2
                        }
                    ],
                    GeneratedAtUtc = DateTimeOffset.UtcNow
                });
        }
    }
}
