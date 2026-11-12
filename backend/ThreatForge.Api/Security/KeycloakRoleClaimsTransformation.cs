
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;

namespace ThreatForge.Api.Security;

public sealed class KeycloakRoleClaimsTransformation
    : IClaimsTransformation
{
    private const string ClientId = "threatforge-api";

    private static readonly HashSet<string> AllowedRoles =
        new(StringComparer.Ordinal)
        {
            "analyst",
            "administrator"
        };

    public Task<ClaimsPrincipal> TransformAsync(
        ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true)
        {
            return Task.FromResult(principal);
        }

        var resourceAccess = principal.FindFirst(
            "resource_access")?.Value;

        if (string.IsNullOrWhiteSpace(resourceAccess))
        {
            return Task.FromResult(principal);
        }

        try
        {
            using var document = JsonDocument.Parse(resourceAccess);

            if (!document.RootElement.TryGetProperty(
                    ClientId, out var client) ||
                !client.TryGetProperty(
                    "roles", out var roles) ||
                roles.ValueKind != JsonValueKind.Array)
            {
                return Task.FromResult(principal);
            }

            var identity = new ClaimsIdentity();

            foreach (var roleElement in roles.EnumerateArray())
            {
                if (roleElement.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                var role = roleElement.GetString();

                if (role is null ||
                    !AllowedRoles.Contains(role) ||
                    principal.IsInRole(role))
                {
                    continue;
                }

                identity.AddClaim(
                    new Claim(ClaimTypes.Role, role));
            }

            if (identity.Claims.Any())
            {
                principal.AddIdentity(identity);
            }
        }
        catch (JsonException)
        {
            // Malformed role claims grant no additional roles.
        }

        return Task.FromResult(principal);
    }
}
