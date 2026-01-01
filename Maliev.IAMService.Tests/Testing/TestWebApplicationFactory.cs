using Maliev.IAMService.Data;
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
    public HttpClient CreateAuthenticatedClientWithAllPermissions(string userId = "test-admin")
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

        var token = CreateTestJwtToken(userId, roles: null, permissions: allPermissions);
        var client = CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        return client;
    }
}
