
using Npgsql;

var builder = WebApplication.CreateBuilder(args);

// Register ASP.NET Core controllers.
builder.Services.AddControllers();

// Register OpenAPI documentation.
builder.Services.AddOpenApi();

// Register the PostgreSQL connection pool.
// Configuration comes from ASP.NET Core User Secrets
// in the Development environment.
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
                "PostgreSQL configuration is incomplete."
            );
        }

        // Prevent accidental connections to the
        // testing or default PostgreSQL databases.
        if (database != "threatforge_db")
        {
            throw new InvalidOperationException(
                "Unexpected PostgreSQL database."
            );
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

        var dataSourceBuilder = new NpgsqlDataSourceBuilder(
            connectionString.ConnectionString
        );

        return dataSourceBuilder.Build();
    });

var app = builder.Build();

// Enable OpenAPI during development.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Register controller routes.
app.MapControllers();

app.Run();

// Required by integration tests.
public partial class Program
{
}
