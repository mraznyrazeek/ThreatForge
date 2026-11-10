
var builder = WebApplication.CreateBuilder(args);

// Register API controllers.
builder.Services.AddControllers();

// Register OpenAPI documentation.
builder.Services.AddOpenApi();

var app = builder.Build();

// Expose OpenAPI in development only.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Map controller-based endpoints.
app.MapControllers();

app.Run();

// Allows future integration tests to host the API.
public partial class Program
{
}
