
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using ThreatForge.Api.Security;
using ThreatForge.Api.Services;

var builder = WebApplication.CreateBuilder(args);

// --------------------------------------------------
// API controllers and OpenAPI
// --------------------------------------------------

builder.Services.AddControllers();
builder.Services.AddOpenApi();

// --------------------------------------------------
// Intelligence and analytics services
// --------------------------------------------------

builder.Services.AddScoped<
    IIntelligenceSummaryService,
    IntelligenceSummaryService>();

builder.Services.AddScoped<
    IThreatIndicatorService,
    ThreatIndicatorService>();

builder.Services.AddScoped<
    IIndicatorDistributionService,
    IndicatorDistributionService>();

builder.Services.AddScoped<
    IMalwareFamilyService,
    MalwareFamilyService>();

builder.Services.AddScoped<
    IDailyThreatActivityService,
    DailyThreatActivityService>();

builder.Services.AddScoped<
    ICrossSourceCorrelationService,
    CrossSourceCorrelationService>();

// --------------------------------------------------
// Keycloak JWT configuration
// --------------------------------------------------

var jwtAuthority = builder.Configuration["Jwt:Authority"];
var jwtAudience = builder.Configuration["Jwt:Audience"];

if (string.IsNullOrWhiteSpace(jwtAuthority) ||
    string.IsNullOrWhiteSpace(jwtAudience))
{
    throw new InvalidOperationException(
        "JWT configuration is incomplete.");
}

if (!Uri.TryCreate(
        jwtAuthority,
        UriKind.Absolute,
        out var authorityUri))
{
    throw new InvalidOperationException(
        "Invalid JWT authority URL.");
}

if (jwtAudience != "threatforge-api")
{
    throw new InvalidOperationException(
        "Unexpected JWT audience.");
}

if (authorityUri.AbsolutePath.TrimEnd('/') !=
    "/realms/threatforge")
{
    throw new InvalidOperationException(
        "Unexpected JWT authority realm.");
}

if (builder.Environment.IsDevelopment())
{
    if (!authorityUri.IsLoopback ||
        (authorityUri.Scheme != Uri.UriSchemeHttp &&
         authorityUri.Scheme != Uri.UriSchemeHttps))
    {
        throw new InvalidOperationException(
            "Development JWT authority must be local.");
    }
}
else if (authorityUri.Scheme != Uri.UriSchemeHttps)
{
    throw new InvalidOperationException(
        "JWT authority must use HTTPS.");
}

// --------------------------------------------------
// JWT bearer authentication
// --------------------------------------------------

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = jwtAuthority;
        options.Audience = jwtAudience;

        options.RequireHttpsMetadata =
            !builder.Environment.IsDevelopment();

        options.MapInboundClaims = false;

        options.TokenValidationParameters =
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtAuthority.TrimEnd('/'),

                ValidateAudience = true,
                ValidAudience = jwtAudience,

                ValidateLifetime = true,
                RequireExpirationTime = true,

                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,

                ClockSkew = TimeSpan.FromSeconds(30),

                RoleClaimType = ClaimTypes.Role
            };
    });

builder.Services.AddTransient<
    IClaimsTransformation,
    KeycloakRoleClaimsTransformation>();

// --------------------------------------------------
// Authorization policies
// --------------------------------------------------

builder.Services.AddAuthorization(options =>
{
    // Do not hardcode the authentication scheme here.
    //
    // Production uses the default JWT bearer scheme.
    // Integration tests can substitute a test-only scheme.
    //
    // Both environments still require an authenticated
    // Analyst or Administrator identity.

    var analystAccessPolicy =
        new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .RequireRole("analyst", "administrator")
            .Build();

    options.AddPolicy(
        "IntelligenceRead",
        analystAccessPolicy);

    options.FallbackPolicy = analystAccessPolicy;

    options.DefaultPolicy = analystAccessPolicy;
});

// --------------------------------------------------
// PostgreSQL connection pool
// --------------------------------------------------

builder.Services.AddSingleton<NpgsqlDataSource>(
    serviceProvider =>
    {
        var configuration = serviceProvider
            .GetRequiredService<IConfiguration>();

        var host = configuration["Database:Host"];
        var portText = configuration["Database:Port"];
        var database = configuration["Database:Name"];
        var username = configuration["Database:Username"];
        var password = configuration["Database:Password"];

        if (string.IsNullOrWhiteSpace(host) ||
            !int.TryParse(portText, out var port) ||
            string.IsNullOrWhiteSpace(username) ||
            string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException(
                "PostgreSQL configuration is incomplete.");
        }

        if (database != "threatforge_db")
        {
            throw new InvalidOperationException(
                "Unexpected PostgreSQL database.");
        }

        var connectionString = new NpgsqlConnectionStringBuilder
        {
            Host = host,
            Port = port,
            Database = database,
            Username = username,
            Password = password,
            Pooling = true,
            Timeout = 5,
            CommandTimeout = 5,
            ApplicationName = "ThreatForge.Api"
        };

        var dataSourceBuilder =
            new NpgsqlDataSourceBuilder(
                connectionString.ConnectionString);

        return dataSourceBuilder.Build();
    });

// --------------------------------------------------
// HTTP middleware
// --------------------------------------------------

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().AllowAnonymous();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

// Required by integration tests.
public partial class Program
{
}
