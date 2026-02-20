using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using Maliev.IAMService.Tests.Testing;
using Xunit;

namespace Maliev.IAMService.Tests.Integration;

public class CoverageBoostTests : BaseIntegrationTest
{
    public CoverageBoostTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task PrincipalsController_GetPrincipals_ReturnsList()
    {
        await CleanDatabaseAsync();

        // Create a principal first
        var request = new CreateServiceAccountRequest
        {
            Name = "test-principal-coverage",
            Description = "Test"
        };
        await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);

        // Act
        var response = await Client.GetAsync("/iam/v1/principals");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<List<PrincipalResponse>>();
        Assert.NotNull(result);
        Assert.NotEmpty(result);
    }

    [Fact]
    public async Task PrincipalsController_GetPrincipalById_ReturnsPrincipal()
    {
        await CleanDatabaseAsync();

        // Create a principal
        var request = new CreateServiceAccountRequest
        {
            Name = "test-by-id",
            Description = "Test"
        };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);
        var created = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        // Act
        var response = await Client.GetAsync($"/iam/v1/principals/{created!.PrincipalId}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<PrincipalResponse>();
        Assert.NotNull(result);
        Assert.Equal(created.PrincipalId, result.PrincipalId);
    }

    [Fact]
    public async Task PrincipalsController_DeletePrincipal_ReturnsNoContent()
    {
        await CleanDatabaseAsync();

        // Create a principal
        var request = new CreateServiceAccountRequest
        {
            Name = "test-delete",
            Description = "Test"
        };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);
        var created = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        // Act
        var response = await Client.DeleteAsync($"/iam/v1/principals/{created!.PrincipalId}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task AuditController_GetAuditLogs_ReturnsLogs()
    {
        await CleanDatabaseAsync();

        // Trigger some action to create audit logs
        var request = new CreateServiceAccountRequest
        {
            Name = "audit-trigger",
            Description = "Test"
        };
        await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);

        // Act
        var response = await Client.GetAsync("/iam/v1/audit/logs?Take=10");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<List<AuditLogEntryResponse>>();
        Assert.NotNull(result);
    }

    [Fact]
    public async Task AuthController_IssueToken_WithResourceScope_ReturnsToken()
    {
        await CleanDatabaseAsync();
        var principalId = await CreateTestPrincipal("resource-scope-boost");
        var request = new IssueTokenRequest
        {
            PrincipalId = principalId.ToString(),
            ResourcePath = "buckets/my-bucket"
        };
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token", request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AuthController_RefreshToken_ReturnsNewToken()
    {
        await CleanDatabaseAsync();
        var principalId = await CreateTestPrincipal("refresh-boost");
        var issueResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token", new IssueTokenRequest { PrincipalId = principalId.ToString() });
        var issueResult = await issueResponse.Content.ReadFromJsonAsync<TokenResponse>();

        var refreshRequest = new RefreshTokenRequest { RefreshToken = issueResult!.RefreshToken };
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token/refresh", refreshRequest);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task RolesController_GetRoles_ReturnsList()
    {
        await CleanDatabaseAsync();
        var response = await Client.GetAsync("/iam/v1/roles");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task RolesController_UpdateRole_ReturnsOk()
    {
        await CleanDatabaseAsync();
        // Create custom role
        var createRequest = new CreateCustomRoleRequest
        {
            RoleId = "roles.test.custom",
            ServiceName = "test",
            Description = "Initial",
            PermissionIds = new List<string>()
        };
        await Client.PostAsJsonAsync("/iam/v1/roles", createRequest);

        var updateRequest = new UpdateRoleRequest { Description = "Updated" };
        var response = await Client.PutAsJsonAsync($"/iam/v1/roles/{createRequest.RoleId}", updateRequest);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task PermissionsController_GetPermissions_ReturnsList()
    {
        await CleanDatabaseAsync();
        var response = await Client.GetAsync("/iam/v1/permissions");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ServiceAccountsController_RotateKey_ReturnsNewKey()
    {
        await CleanDatabaseAsync();
        var principalId = await CreateTestPrincipal("rotate-boost");
        var response = await Client.PostAsync($"/iam/v1/service-accounts/{principalId}/rotate-key", null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task PermissionsController_GetPermissionById_ReturnsOk()
    {
        await CleanDatabaseAsync();
        var serviceName = "boost-service";
        var request = new RegisterPermissionsRequest
        {
            ServiceName = serviceName,
            Permissions = new List<PermissionDto> { new() { PermissionId = $"{serviceName}.test.perm", Description = "Test" } }
        };
        await Client.PostAsJsonAsync("/iam/v1/permissions/register", request);

        var response = await Client.GetAsync($"/iam/v1/permissions/{Uri.EscapeDataString($"{serviceName}.test.perm")}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task RolesController_GetRoleById_ReturnsOk()
    {
        await CleanDatabaseAsync();
        var serviceName = "boost-role-service";
        var request = new RegisterRolesRequest
        {
            ServiceName = serviceName,
            Roles = new List<RoleDto> { new() { RoleId = $"roles.{serviceName}.admin", Description = "Admin", PermissionIds = new List<string>() } }
        };
        await Client.PostAsJsonAsync("/iam/v1/roles/register", request);

        var response = await Client.GetAsync($"/iam/v1/roles/{Uri.EscapeDataString($"roles.{serviceName}.admin")}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AuditController_GetAuditLogsFilters_ReturnsLogs()
    {
        await CleanDatabaseAsync();
        var principalId = Guid.NewGuid();
        var response1 = await Client.GetAsync($"/iam/v1/audit/logs?PrincipalId={principalId}");
        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);

        var response2 = await Client.GetAsync("/iam/v1/audit/logs?Action=Create");
        Assert.Equal(HttpStatusCode.OK, response2.StatusCode);

        var response3 = await Client.GetAsync($"/iam/v1/audit/logs?FromDate={DateTime.UtcNow.AddDays(-1):O}&ToDate={DateTime.UtcNow.AddDays(1):O}");
        Assert.Equal(HttpStatusCode.OK, response3.StatusCode);
    }

    [Fact]
    public async Task ServiceAccountsController_GetEffectivePermissions_ReturnsOk()
    {
        await CleanDatabaseAsync();
        var principalId = await CreateTestPrincipal("effective-boost");
        var response = await Client.GetAsync($"/iam/v1/service-accounts/{principalId}/effective-permissions?resourceType=bucket&resourceId=123");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task PrincipalsController_GetBootstrapStatus_ReturnsOk()
    {
        await CleanDatabaseAsync();
        var response = await Client.GetAsync("/iam/v1/principals/bootstrap/status");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task PrincipalsController_PromoteCallerToAdmin_WhenAlreadyBootstrapped_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        await Client.PostAsJsonAsync("/iam/v1/principals", new CreatePrincipalRequest { PrincipalType = "user", Email = "bootstrap1@example.com" });
        await Client.PostAsJsonAsync("/iam/v1/principals", new CreatePrincipalRequest { PrincipalType = "user", Email = "bootstrap2@example.com" });

        var response = await Client.PostAsync("/iam/v1/principals/bootstrap/promote", null);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task PrincipalsController_CreatePrincipal_ReturnsCreated()
    {
        await CleanDatabaseAsync();

        var request = new CreatePrincipalRequest
        {
            PrincipalType = "user",
            Email = "create-principal@example.com",
            DisplayName = "Test User"
        };
        var response = await Client.PostAsJsonAsync("/iam/v1/principals", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task PrincipalsController_GetPrincipalByEmail_WhenExists_ReturnsOk()
    {
        await CleanDatabaseAsync();

        const string email = "find-by-email@example.com";
        await Client.PostAsJsonAsync("/iam/v1/principals", new CreatePrincipalRequest { PrincipalType = "user", Email = email });

        var response = await Client.GetAsync($"/iam/v1/principals/by-email/{Uri.EscapeDataString(email)}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<PrincipalResponse>();
        Assert.NotNull(result);
        Assert.Equal(email, result.Email);
    }

    [Fact]
    public async Task PrincipalsController_GetPrincipalByEmail_WhenNotFound_ReturnsNotFound()
    {
        await CleanDatabaseAsync();

        await Client.PostAsJsonAsync("/iam/v1/principals", new CreatePrincipalRequest { PrincipalType = "user", Email = "exists@example.com" });

        var response = await Client.GetAsync($"/iam/v1/principals/by-email/{Uri.EscapeDataString("nonexistent@example.com")}");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task AuthController_CheckPermission_ReturnsOk()
    {
        await CleanDatabaseAsync();
        var principalId = await CreateTestPrincipal("check-perm-boost");

        var request = new CheckPermissionRequest
        {
            PrincipalId = principalId.ToString(),
            PermissionId = "iam.principals.list"
        };
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/check-permission", request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ResolvePermissions_NonExistentPrincipal_ReturnsOkWithEmptyPermissions()
    {
        await CleanDatabaseAsync();

        // PrincipalId that is not a GUID and does not exist in the DB
        // triggers the InvalidOperationException catch block in PermissionResolver
        var request = new ResolvePermissionsRequest { PrincipalId = "nonexistent-user@fake-domain.test" };
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/resolve-permissions", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<ResolvePermissionsResponse>();
        Assert.NotNull(result);
        Assert.Empty(result.Permissions);
    }

    [Fact]
    public async Task BulkCheckPermissions_ReturnsDictionary()
    {
        await CleanDatabaseAsync();
        var principalId = await CreateTestPrincipal("bulk-check-boost");

        var request = new BulkCheckPermissionRequest
        {
            PrincipalId = principalId.ToString(),
            PermissionChecks = new List<PermissionCheckItem>
            {
                new() { PermissionId = "iam.principals.list" },
                new() { PermissionId = "iam.roles.read", ResourcePath = "projects/123" }
            }
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/auth/check-permissions", request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var result = await response.Content.ReadFromJsonAsync<Dictionary<string, bool>>();
        Assert.NotNull(result);
        Assert.Equal(2, result.Count);
        Assert.Contains("iam.principals.list", result.Keys);
    }

    [Fact]
    public async Task GetEffectivePermissions_WithGrantedRole_ReturnsPermissions()
    {
        await CleanDatabaseAsync();

        // Register a permission + role
        var permRequest = new RegisterPermissionsRequest
        {
            ServiceName = "eff-perm-service",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = "eff-perm-service.data.read", Description = "Read" }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/permissions/register", permRequest);

        var roleRequest = new RegisterRolesRequest
        {
            ServiceName = "eff-perm-service",
            Roles = new List<RoleDto>
            {
                new() { RoleId = "roles.eff-perm-service.reader", Description = "Reader",
                        PermissionIds = new List<string> { "eff-perm-service.data.read" } }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/roles/register", roleRequest);

        // Create principal + grant role
        var principalId = await CreateTestPrincipal("eff-perm-principal");
        var grantRequest = new GrantRoleRequest { RoleId = "roles.eff-perm-service.reader" };
        await Client.PostAsJsonAsync($"/iam/v1/principals/{principalId}/roles", grantRequest);

        // Get effective permissions - should now include the permission
        var response = await Client.GetAsync($"/iam/v1/service-accounts/{principalId}/effective-permissions");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var result = await response.Content.ReadFromJsonAsync<EffectivePermissionsResponse>();
        Assert.NotNull(result);
        Assert.NotEmpty(result.Permissions);
        Assert.Contains(result.Permissions, p => p.PermissionId == "eff-perm-service.data.read");
    }

    [Fact]
    public async Task GetLivenessEndpoint_ReturnsHealthy()
    {
        var response = await Client.GetAsync("/iam/liveness");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GetReadinessEndpoint_ReturnsResponse()
    {
        // The readiness check always returns a response (healthy or unhealthy)
        // In tests, IAMInitializationHostedService is disabled, so it returns unhealthy
        var response = await Client.GetAsync("/iam/readiness");
        // Assert it returns a valid response (200 or 503)
        Assert.True(response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.ServiceUnavailable);
    }

    private async Task<Guid> CreateTestPrincipal(string name)
    {
        var request = new CreateServiceAccountRequest { Name = name };
        var response = await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);
        var result = await response.Content.ReadFromJsonAsync<ServiceAccountResponse>();
        return result!.PrincipalId;
    }
}
