
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
                    // Authenticate integration test requests
                    // using the test-only Analyst identity.
                    // Production continues to use Keycloak JWTs.
                    TestAuthenticationConfiguration
                        .AddTestAuthentication(services);

                    // Replace the PostgreSQL-backed service
                    // with deterministic test data.
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
            using var response = await client.GetAsync(
                "/api/v1/intelligence/indicators");

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
            var result = await client.GetFromJsonAsync<
                PagedIndicatorsResponse>(
                "/api/v1/intelligence/indicators?page=1&pageSize=5");

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
                "/api/v1/intelligence/indicators" +
                "?type=sha256_hash&page=2&pageSize=10");

            Assert.Equal(
                HttpStatusCode.OK,
                response.StatusCode);

            Assert.Equal(2, service.LastPage);
            Assert.Equal(10, service.LastPageSize);
            Assert.Equal(
                "sha256_hash",
                service.LastIndicatorType);
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
                "/api/v1/intelligence/indicators" + query);

            Assert.Equal(
                HttpStatusCode.BadRequest,
                response.StatusCode);

            // Invalid requests must not reach the service.
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
                "/api/v1/intelligence/indicators?type=" +
                longType);

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
            var result = await client.GetFromJsonAsync<
                PagedIndicatorsResponse>(
                "/api/v1/intelligence/indicators?type=unknown");

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
            var result = await client.GetFromJsonAsync<
                PagedIndicatorsResponse>(
                "/api/v1/intelligence/indicators?page=2&pageSize=5");

            Assert.NotNull(result);
            Assert.Equal(2, result.Page);
            Assert.True(result.HasPreviousPage);
            Assert.True(result.HasNextPage);
        }
    }

    private sealed class FakeIndicatorService
        : IThreatIndicatorService
    {
        public int CallCount { get; private set; }

        public int LastPage { get; private set; }

        public int LastPageSize { get; private set; }

        public string? LastIndicatorType { get; private set; }

        public bool ReturnEmpty { get; set; }

        public Task<PagedIndicatorsResponse> GetIndicatorsAsync(
            int page,
            int pageSize,
            string? indicatorType,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            LastPage = page;
            LastPageSize = pageSize;
            LastIndicatorType = indicatorType;

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
    }
}
