
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

public sealed class IndicatorDistributionEndpointTests
{
    private const string Endpoint =
        "/api/v1/analytics/indicators/distribution";

    private static (
        WebApplicationFactory<Program> Factory,
        FakeIndicatorDistributionService Service
    ) CreateFactory()
    {
        var service = new FakeIndicatorDistributionService();

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

                    // Replace the PostgreSQL-backed service
                    // with deterministic test data.
                    services.RemoveAll<
                        IIndicatorDistributionService>();

                    services.AddSingleton<
                        IIndicatorDistributionService>(service);
                });
            });

        return (factory, service);
    }

    [Fact]
    public async Task GetDistribution_ReturnsHttp200()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            using var response = await client.GetAsync(Endpoint);

            Assert.Equal(
                HttpStatusCode.OK,
                response.StatusCode);
        }
    }

    [Fact]
    public async Task GetDistribution_ReturnsExpectedTotal()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result = await client.GetFromJsonAsync<
                IndicatorDistributionResponse>(Endpoint);

            Assert.NotNull(result);
            Assert.Equal(100, result.TotalIndicators);
            Assert.Equal(3, result.Distribution.Count);
        }
    }

    [Fact]
    public async Task GetDistribution_ReturnsCorrectCategories()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result = await client.GetFromJsonAsync<
                IndicatorDistributionResponse>(Endpoint);

            Assert.NotNull(result);

            Assert.Collection(
                result.Distribution,
                item =>
                {
                    Assert.Equal("sha256_hash", item.IndicatorType);
                    Assert.Equal(50, item.Count);
                    Assert.Equal(50m, item.Percentage);
                },
                item =>
                {
                    Assert.Equal("domain", item.IndicatorType);
                    Assert.Equal(30, item.Count);
                    Assert.Equal(30m, item.Percentage);
                },
                item =>
                {
                    Assert.Equal("url", item.IndicatorType);
                    Assert.Equal(20, item.Count);
                    Assert.Equal(20m, item.Percentage);
                });
        }
    }

    [Fact]
    public async Task GetDistribution_CountsReconcile()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result = await client.GetFromJsonAsync<
                IndicatorDistributionResponse>(Endpoint);

            Assert.NotNull(result);

            Assert.Equal(
                result.TotalIndicators,
                result.Distribution.Sum(x => x.Count));

            Assert.Equal(
                100m,
                result.Distribution.Sum(x => x.Percentage));
        }
    }

    [Fact]
    public async Task GetDistribution_EmptyDataset_ReturnsValidResponse()
    {
        var (factory, service) = CreateFactory();
        service.ReturnEmpty = true;

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result = await client.GetFromJsonAsync<
                IndicatorDistributionResponse>(Endpoint);

            Assert.NotNull(result);
            Assert.Equal(0, result.TotalIndicators);
            Assert.Empty(result.Distribution);
        }
    }

    [Fact]
    public async Task GetDistribution_ReturnsUtcTimestampAndJson()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            using var response = await client.GetAsync(Endpoint);

            Assert.Equal(
                "application/json",
                response.Content.Headers.ContentType?.MediaType);

            var result = await response.Content
                .ReadFromJsonAsync<IndicatorDistributionResponse>();

            Assert.NotNull(result);

            Assert.Equal(
                TimeSpan.Zero,
                result.GeneratedAtUtc.Offset);

            Assert.True(
                result.GeneratedAtUtc <= DateTimeOffset.UtcNow);
        }
    }

    private sealed class FakeIndicatorDistributionService
        : IIndicatorDistributionService
    {
        public bool ReturnEmpty { get; set; }

        public Task<IndicatorDistributionResponse>
            GetDistributionAsync(
                CancellationToken cancellationToken = default)
        {
            IReadOnlyList<IndicatorDistributionItem> items =
                ReturnEmpty
                    ? []
                    :
                    [
                        new IndicatorDistributionItem
                        {
                            IndicatorType = "sha256_hash",
                            Count = 50,
                            Percentage = 50m
                        },
                        new IndicatorDistributionItem
                        {
                            IndicatorType = "domain",
                            Count = 30,
                            Percentage = 30m
                        },
                        new IndicatorDistributionItem
                        {
                            IndicatorType = "url",
                            Count = 20,
                            Percentage = 20m
                        }
                    ];

            var result = new IndicatorDistributionResponse
            {
                TotalIndicators = ReturnEmpty ? 0 : 100,
                Distribution = items,
                GeneratedAtUtc = DateTimeOffset.UtcNow
            };

            return Task.FromResult(result);
        }
    }
}
