
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ThreatForge.Api.Models;
using ThreatForge.Api.Services;
using Xunit;

namespace ThreatForge.Api.Tests;

public sealed class DailyThreatActivityEndpointTests
{
    private const string Endpoint =
        "/api/v1/analytics/temporal/daily";

    private static (
        WebApplicationFactory<Program> Factory,
        FakeDailyActivityService Service
    ) CreateFactory()
    {
        var service = new FakeDailyActivityService();

        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureTestServices(services =>
                {
                    services.RemoveAll<
                        IDailyThreatActivityService>();

                    services.AddSingleton<
                        IDailyThreatActivityService>(service);

                    services.RemoveAll<
                        IIndicatorDistributionService>();

                    services.AddSingleton<
                        IIndicatorDistributionService,
                        FakeDistributionService>();

                    services.RemoveAll<IMalwareFamilyService>();

                    services.AddSingleton<
                        IMalwareFamilyService,
                        FakeMalwareFamilyService>();
                });
            });

        return (factory, service);
    }

    [Fact]
    public async Task GetDailyActivity_ReturnsHttp200()
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
    public async Task GetDailyActivity_ReturnsExpectedTotal()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result = await client.GetFromJsonAsync<
                DailyThreatActivityResponse>(Endpoint);

            Assert.NotNull(result);
            Assert.Equal("UTC", result.Timezone);
            Assert.Equal(6, result.TotalObservations);
            Assert.Equal(3, result.DailyActivity.Count);
        }
    }

    [Fact]
    public async Task GetDailyActivity_ReturnsCorrectSourceCounts()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result = await client.GetFromJsonAsync<
                DailyThreatActivityResponse>(Endpoint);

            Assert.NotNull(result);

            Assert.Collection(
                result.DailyActivity,
                item =>
                {
                    Assert.Equal(
                        new DateOnly(2026, 11, 8),
                        item.DateUtc);

                    Assert.Equal(
                        "ThreatFox",
                        item.SourceName);

                    Assert.Equal(3, item.ObservationCount);
                    Assert.Equal(2, item.DistinctIndicatorCount);
                },
                item =>
                {
                    Assert.Equal(
                        new DateOnly(2026, 11, 8),
                        item.DateUtc);

                    Assert.Equal(
                        "URLhaus",
                        item.SourceName);

                    Assert.Equal(1, item.ObservationCount);
                    Assert.Equal(1, item.DistinctIndicatorCount);
                },
                item =>
                {
                    Assert.Equal(
                        new DateOnly(2026, 11, 9),
                        item.DateUtc);

                    Assert.Equal(
                        "ThreatFox",
                        item.SourceName);

                    Assert.Equal(2, item.ObservationCount);
                    Assert.Equal(2, item.DistinctIndicatorCount);
                });
        }
    }

    [Fact]
    public async Task GetDailyActivity_ObservationCountsReconcile()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result = await client.GetFromJsonAsync<
                DailyThreatActivityResponse>(Endpoint);

            Assert.NotNull(result);

            Assert.Equal(
                result.TotalObservations,
                result.DailyActivity.Sum(
                    item => item.ObservationCount));

            Assert.All(result.DailyActivity, item =>
            {
                Assert.True(
                    item.DistinctIndicatorCount
                    <= item.ObservationCount);
            });
        }
    }

    [Fact]
    public async Task GetDailyActivity_EmptyDatasetReturns200()
    {
        var (factory, service) = CreateFactory();
        service.ReturnEmpty = true;

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result = await client.GetFromJsonAsync<
                DailyThreatActivityResponse>(Endpoint);

            Assert.NotNull(result);
            Assert.Equal("UTC", result.Timezone);
            Assert.Equal(0, result.TotalObservations);
            Assert.Empty(result.DailyActivity);
        }
    }

    [Fact]
    public async Task GetDailyActivity_ReturnsUtcTimestampAndJson()
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
                .ReadFromJsonAsync<DailyThreatActivityResponse>();

            Assert.NotNull(result);

            Assert.Equal(
                TimeSpan.Zero,
                result.GeneratedAtUtc.Offset);

            Assert.True(
                result.GeneratedAtUtc <= DateTimeOffset.UtcNow);
        }
    }

    private sealed class FakeDailyActivityService
        : IDailyThreatActivityService
    {
        public bool ReturnEmpty { get; set; }

        public Task<DailyThreatActivityResponse>
            GetDailyActivityAsync(
                CancellationToken cancellationToken = default)
        {
            IReadOnlyList<DailyThreatActivityItem> items =
                ReturnEmpty
                    ? []
                    :
                    [
                        new DailyThreatActivityItem
                        {
                            DateUtc = new DateOnly(2026, 11, 8),
                            SourceName = "ThreatFox",
                            ObservationCount = 3,
                            DistinctIndicatorCount = 2
                        },
                        new DailyThreatActivityItem
                        {
                            DateUtc = new DateOnly(2026, 11, 8),
                            SourceName = "URLhaus",
                            ObservationCount = 1,
                            DistinctIndicatorCount = 1
                        },
                        new DailyThreatActivityItem
                        {
                            DateUtc = new DateOnly(2026, 11, 9),
                            SourceName = "ThreatFox",
                            ObservationCount = 2,
                            DistinctIndicatorCount = 2
                        }
                    ];

            return Task.FromResult(
                new DailyThreatActivityResponse
                {
                    Timezone = "UTC",
                    TotalObservations = ReturnEmpty ? 0 : 6,
                    DailyActivity = items,
                    GeneratedAtUtc = DateTimeOffset.UtcNow
                });
        }
    }

    private sealed class FakeDistributionService
        : IIndicatorDistributionService
    {
        public Task<IndicatorDistributionResponse>
            GetDistributionAsync(
                CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new IndicatorDistributionResponse
                {
                    TotalIndicators = 0,
                    Distribution = [],
                    GeneratedAtUtc = DateTimeOffset.UtcNow
                });
        }
    }

    private sealed class FakeMalwareFamilyService
        : IMalwareFamilyService
    {
        public Task<MalwareFamilyResponse> GetTopFamiliesAsync(
            int limit,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new MalwareFamilyResponse
                {
                    Limit = limit,
                    Families = [],
                    GeneratedAtUtc = DateTimeOffset.UtcNow
                });
        }
    }
}
