
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

public sealed class ThreatIndicatorsEndpointTests
{
    private const string Endpoint =
        "/api/v1/intelligence/indicators";

    private static (
        WebApplicationFactory<Program> Factory,
        FakeIndicatorService Service
    ) CreateFactory()
    {
        var service = new FakeIndicatorService();

        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureTestServices(services =>
                {
                    // Use the test-only Analyst identity.
                    // Production continues to use Keycloak JWTs.
                    TestAuthenticationConfiguration
                        .AddTestAuthentication(services);

                    // Replace the PostgreSQL-backed service
                    // with a deterministic fake.
                    services.RemoveAll<IThreatIndicatorService>();

                    services.AddSingleton<IThreatIndicatorService>(
                        service);
                });
            });

        return (factory, service);
    }

    [Fact]
    public async Task GetIndicators_ReturnsHttp200()
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
    public async Task GetIndicators_ReturnsPaginationMetadata()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result =
                await client.GetFromJsonAsync<PagedIndicatorsResponse>(
                    Endpoint + "?page=1&pageSize=5");

            Assert.NotNull(result);
            Assert.Equal(1, result.Page);
            Assert.Equal(5, result.PageSize);
            Assert.Equal(100, result.TotalItems);
            Assert.Equal(20, result.TotalPages);
            Assert.True(result.HasNextPage);
            Assert.False(result.HasPreviousPage);
            Assert.Equal(5, result.Items.Count);
        }
    }

    [Fact]
    public async Task GetIndicators_ForwardsTypeAndPagination()
    {
        var (factory, service) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            using var response = await client.GetAsync(
                Endpoint +
                "?type=sha256_hash&page=2&pageSize=10");

            Assert.Equal(
                HttpStatusCode.OK,
                response.StatusCode);

            Assert.Equal(1, service.CallCount);
            Assert.Equal(2, service.LastPage);
            Assert.Equal(10, service.LastPageSize);
            Assert.Equal(
                "sha256_hash",
                service.LastIndicatorType);
            Assert.Null(service.LastSearch);
        }
    }

    [Fact]
    public async Task GetIndicators_ForwardsSearch()
    {
        var (factory, service) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            using var response = await client.GetAsync(
                Endpoint + "?search=aldoku77.org");

            Assert.Equal(
                HttpStatusCode.OK,
                response.StatusCode);

            Assert.Equal(1, service.CallCount);
            Assert.Equal(
                "aldoku77.org",
                service.LastSearch);
            Assert.Null(service.LastIndicatorType);
        }
    }

    [Fact]
    public async Task GetIndicators_ForwardsCombinedFiltersAndPagination()
    {
        var (factory, service) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            using var response = await client.GetAsync(
                Endpoint +
                "?type=url&search=aldoku77.org" +
                "&page=2&pageSize=10");

            Assert.Equal(
                HttpStatusCode.OK,
                response.StatusCode);

            Assert.Equal(1, service.CallCount);
            Assert.Equal("url", service.LastIndicatorType);
            Assert.Equal(
                "aldoku77.org",
                service.LastSearch);
            Assert.Equal(2, service.LastPage);
            Assert.Equal(10, service.LastPageSize);
        }
    }

    [Theory]
    [InlineData("%")]
    [InlineData("_")]
    [InlineData("\\")]
    [InlineData("https://example.org/path?a=1&b=2")]
    public async Task GetIndicators_ForwardsSpecialCharacters(
        string search)
    {
        var (factory, service) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var encodedSearch = Uri.EscapeDataString(search);

            using var response = await client.GetAsync(
                Endpoint + "?search=" + encodedSearch);

            Assert.Equal(
                HttpStatusCode.OK,
                response.StatusCode);

            Assert.Equal(1, service.CallCount);
            Assert.Equal(search, service.LastSearch);
        }
    }

    [Theory]
    [InlineData("?page=0")]
    [InlineData("?pageSize=0")]
    [InlineData("?pageSize=101")]
    public async Task GetIndicators_InvalidPagination_Returns400(
        string query)
    {
        var (factory, service) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            using var response = await client.GetAsync(
                Endpoint + query);

            Assert.Equal(
                HttpStatusCode.BadRequest,
                response.StatusCode);

            Assert.Equal(0, service.CallCount);
        }
    }

    [Fact]
    public async Task GetIndicators_LongType_Returns400()
    {
        var (factory, service) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var longType = new string('x', 65);

            using var response = await client.GetAsync(
                Endpoint + "?type=" + longType);

            Assert.Equal(
                HttpStatusCode.BadRequest,
                response.StatusCode);

            Assert.Equal(0, service.CallCount);
        }
    }

    [Fact]
    public async Task GetIndicators_LongSearch_Returns400()
    {
        var (factory, service) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var longSearch = new string('x', 257);

            using var response = await client.GetAsync(
                Endpoint + "?search=" + longSearch);

            Assert.Equal(
                HttpStatusCode.BadRequest,
                response.StatusCode);

            Assert.Equal(0, service.CallCount);
        }
    }

    [Fact]
    public async Task GetIndicators_EmptyResults_Returns200()
    {
        var (factory, service) = CreateFactory();

        service.ReturnEmpty = true;

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result =
                await client.GetFromJsonAsync<PagedIndicatorsResponse>(
                    Endpoint + "?type=unknown");

            Assert.NotNull(result);
            Assert.Empty(result.Items);
            Assert.Equal(0, result.TotalItems);
            Assert.Equal(0, result.TotalPages);
            Assert.False(result.HasNextPage);
        }
    }

    [Fact]
    public async Task GetIndicators_SecondPageMetadata()
    {
        var (factory, _) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            var result =
                await client.GetFromJsonAsync<PagedIndicatorsResponse>(
                    Endpoint + "?page=2&pageSize=5");

            Assert.NotNull(result);
            Assert.Equal(2, result.Page);
            Assert.True(result.HasPreviousPage);
            Assert.True(result.HasNextPage);
        }
    }

    [Fact]
    public async Task GetIndicatorById_UnknownIndicator_Returns404()
    {
        var (factory, service) = CreateFactory();

        using (factory)
        using (var client = factory.CreateClient())
        {
            using var response = await client.GetAsync(
                Endpoint + "/999999");

            Assert.Equal(
                HttpStatusCode.NotFound,
                response.StatusCode);

            Assert.Equal(1, service.DetailCallCount);
            Assert.Equal(999999L, service.LastDetailId);
        }
    }

    private sealed class FakeIndicatorService
        : IThreatIndicatorService
    {
        public int CallCount { get; private set; }

        public int LastPage { get; private set; }

        public int LastPageSize { get; private set; }

        public string? LastIndicatorType { get; private set; }

        public string? LastSearch { get; private set; }

        public bool ReturnEmpty { get; set; }

        public int DetailCallCount { get; private set; }

        public long LastDetailId { get; private set; }

        public Task<PagedIndicatorsResponse> GetIndicatorsAsync(
            int page,
            int pageSize,
            string? indicatorType,
            string? search,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            LastPage = page;
            LastPageSize = pageSize;
            LastIndicatorType = indicatorType;
            LastSearch = search;

            var total = ReturnEmpty ? 0L : 100L;

            var totalPages = total == 0
                ? 0
                : (total + pageSize - 1) / pageSize;

            var items = ReturnEmpty
            ? new List<IndicatorListItem>()
            : Enumerable.Range(1, pageSize)
                .Select(i => new IndicatorListItem
                {
                    Id = ((long)page - 1) * pageSize + i,
                    IndicatorType = indicatorType ?? "domain",
                    NormalizedValue = $"test-indicator-{i}.example.org",
                    ObservationCount = 1,
                    CreatedAtUtc = DateTimeOffset.UtcNow
                })
                .ToList();

            return Task.FromResult(
                new PagedIndicatorsResponse
                {
                    Items = items,
                    Page = page,
                    PageSize = pageSize,
                    TotalItems = total,
                    TotalPages = totalPages,
                    HasNextPage = page < totalPages,
                    HasPreviousPage = page > 1
                });
        }

        public Task<IndicatorDetailResponse?> GetIndicatorByIdAsync(
            long id,
            CancellationToken cancellationToken = default)
        {
            DetailCallCount++;
            LastDetailId = id;

            // Simulate a missing indicator.
            return Task.FromResult<IndicatorDetailResponse?>(null);
        }
    }
}
