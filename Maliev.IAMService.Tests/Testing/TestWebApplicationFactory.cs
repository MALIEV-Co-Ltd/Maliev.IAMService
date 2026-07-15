using Maliev.IAMService.Infrastructure.Persistence;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authorization;
using Maliev.Aspire.ServiceDefaults.Authorization;

namespace Maliev.IAMService.Tests.Testing;

public class TestWebApplicationFactory : BaseIntegrationTestFactory<Program, IAMDbContext>
{
    protected override string DbConnectionStringName => "IamDbContext";

    protected override void ConfigureAdditionalServices(IServiceCollection services)
    {
        // Add permission-based authorization infrastructure for tests
        services.AddHttpContextAccessor();
        services.AddSingleton<IAuthorizationPolicyProvider, PermissionAuthorizationPolicyProvider>();
        services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
        services.AddAuthorizationBuilder();
    }

    /// <summary>
    /// Creates an authenticated HTTP client with all IAM permissions for testing.
    /// </summary>
    public HttpClient CreateAuthenticatedClientWithAllPermissions(string userId = "00000000-0000-0000-0000-000000000002")
    {
        var allPermissions = new[]
        {
            // Principals
            "iam.principals.create", "iam.principals.read", "iam.principals.update",
            "iam.principals.delete", "iam.principals.list", "iam.principals.get",
            // Roles
            "iam.roles.create", "iam.roles.read", "iam.roles.update",
            "iam.roles.delete", "iam.roles.list", "iam.roles.register",
            // Permissions
            "iam.permissions.create", "iam.permissions.read", "iam.permissions.update",
            "iam.permissions.delete", "iam.permissions.list", "iam.permissions.register",
            "iam.permissions.check", "iam.permissions.batch-check", "iam.permissions.effective",
            // Bindings
            "iam.bindings.create", "iam.bindings.read", "iam.bindings.delete",
            "iam.bindings.list", "iam.bindings.grant", "iam.bindings.revoke",
            // Auth
            "iam.auth.resolve-permissions", "iam.auth.check-permission",
            "iam.auth.issue-token", "iam.auth.refresh-token",
            "iam.tokens.issue", "iam.tokens.refresh",
            // Service Accounts
            "iam.service-accounts.create", "iam.service-accounts.generate-key",
            "iam.service-accounts.revoke-key", "iam.service-accounts.rotate-key",
            // Audit
            "iam.audit.read", "iam.audit.list", "iam.audit.view"
        };

        var token = CreateTestJwtToken(userId, roles: new[] { "service-account" }, permissions: allPermissions);
        var client = CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        return client;
    }

    /// <summary>
    /// Creates a client whose claims match the production service-token shape used for live IAM checks.
    /// </summary>
    /// <param name="serviceName">Service name carried by the token.</param>
    /// <returns>An authenticated service client with permission-check access.</returns>
    public HttpClient CreateLivePermissionCheckServiceClient(string serviceName = "IntranetBff")
    {
        var canonicalSubject = $"system:service:{serviceName.ToLowerInvariant().Replace("service", string.Empty, StringComparison.Ordinal)}";
        var token = CreateTestJwtToken(
            canonicalSubject,
            roles: ["service-account"],
            permissions: ["iam.auth.check-permission"],
            additionalClaims: new Dictionary<string, string>
            {
                ["service_name"] = serviceName,
                ["user_type"] = "service",
                ["purpose"] = "iam-registration"
            });
        var client = CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        client.DefaultRequestHeaders.Add("X-Maliev-IAM-Live-Check-Key", LiveCheckTestCredential);
        return client;
    }
}
