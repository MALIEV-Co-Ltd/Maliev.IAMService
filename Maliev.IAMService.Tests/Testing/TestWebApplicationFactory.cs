using Maliev.IAMService.Infrastructure.Persistence;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authorization;
using Maliev.Aspire.ServiceDefaults.Authorization;
using System.Security.Claims;

namespace Maliev.IAMService.Tests.Testing;

public class TestWebApplicationFactory : BaseIntegrationTestFactory<Program, IAMDbContext>
{
    private static readonly string[] AllPermissions =
    [
        "iam.principals.create", "iam.principals.read", "iam.principals.update",
        "iam.principals.delete", "iam.principals.list", "iam.principals.get",
        "iam.roles.create", "iam.roles.read", "iam.roles.update",
        "iam.roles.delete", "iam.roles.list", "iam.roles.register",
        "iam.permissions.create", "iam.permissions.read", "iam.permissions.update",
        "iam.permissions.delete", "iam.permissions.list", "iam.permissions.register",
        "iam.permissions.check", "iam.permissions.batch-check", "iam.permissions.effective",
        "iam.bindings.create", "iam.bindings.read", "iam.bindings.delete",
        "iam.bindings.list", "iam.bindings.grant", "iam.bindings.revoke",
        "iam.auth.resolve-permissions", "iam.auth.check-permission",
        "iam.auth.issue-token", "iam.auth.refresh-token",
        "iam.tokens.issue", "iam.tokens.refresh",
        "iam.service-accounts.create", "iam.service-accounts.generate-key",
        "iam.service-accounts.revoke-key", "iam.service-accounts.rotate-key",
        "iam.audit.read", "iam.audit.list", "iam.audit.view",
        "iam.workload-principals.provision"
    ];

    protected override string DbConnectionStringName => "IamDbContext";

    /// <summary>Gets the PostgreSQL connection string for isolated schema migration tests.</summary>
    public string MigrationTestConnectionString => PostgreSqlConnectionString;

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
        var token = CreateTestJwtToken(userId, roles: ["service-account"], permissions: AllPermissions);
        var client = CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        return client;
    }

    /// <summary>Creates an explicit employee administrator client for employee-only IAM operations.</summary>
    /// <param name="principalId">Canonical employee principal ID.</param>
    /// <param name="repeatedClaims">Optional repeated claims for negative contract tests.</param>
    /// <returns>Authenticated employee client.</returns>
    public HttpClient CreateEmployeeAdminClient(Guid principalId, params Claim[] repeatedClaims)
    {
        var token = CreateTestJwtToken(
            principalId.ToString("D"),
            roles: ["employee"],
            permissions: AllPermissions,
            additionalClaims: new Dictionary<string, string> { ["user_type"] = "employee" },
            repeatedClaims: repeatedClaims);
        var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
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
