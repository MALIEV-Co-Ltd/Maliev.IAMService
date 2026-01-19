using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using Maliev.IAMService.Tests.Testing;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Integration tests for Bindings Controller.
/// Tests role binding/unbinding to principals and resource-scoped bindings.
/// </summary>

public class BindingsControllerTests : BaseIntegrationTest
{
    public BindingsControllerTests(TestWebApplicationFactory factory) : base(factory)
    {
    }





    private async Task<(Guid principalId, string roleId)> SetupPrincipalAndRole(string testName)
    {
        // Create service account
        var principalRequest = new CreateServiceAccountRequest
        {
            Name = $"test-account-{testName}",
            Description = $"Account for {testName}"
        };
        var principalResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", principalRequest);
        var statusCode = principalResponse.StatusCode;
        var content = await principalResponse.Content.ReadAsStringAsync();
        if (!principalResponse.IsSuccessStatusCode || string.IsNullOrEmpty(content))
        {
            throw new Exception($"Failed to create service account. Status: {statusCode}, Content: '{content}'");
        }
        var principal = await principalResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        // Register permissions
        var serviceName = $"binding-service-{testName}";
        var permRequest = new RegisterPermissionsRequest
        {
            ServiceName = serviceName,
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = $"{serviceName}.data.read", Description = "Read" }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/permissions/register", permRequest);

        // Register role
        var roleRequest = new RegisterRolesRequest
        {
            ServiceName = serviceName,
            Roles = new List<RoleDto>
            {
                new()
                {
                    RoleId = $"roles.{serviceName}.reader",
                    Description = "Reader role",
                    PermissionIds = new List<string> { $"{serviceName}.data.read" },
                    IsCustom = false
                }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/roles/register", roleRequest);

        return (principal!.PrincipalId, $"roles.{serviceName}.reader");
    }

    [Fact]
    public async Task GrantRole_ValidRequest_ReturnsOk()
    {
        await CleanDatabaseAsync();

        // Arrange
        var (principalId, roleId) = await SetupPrincipalAndRole("grant-valid");
        var request = new GrantRoleRequest
        {
            RoleId = roleId
        };

        // Act
        var response = await Client.PostAsJsonAsync($"/iam/v1/principals/{principalId}/roles", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<RoleBindingResponse>();
        Assert.NotNull(result);
        Assert.Equal(principalId, result.PrincipalId);
        Assert.Equal(roleId, result.RoleId);
    }

    [Fact]
    public async Task GrantRole_WithResourceScope_ReturnsOk()
    {
        await CleanDatabaseAsync();

        // Arrange
        var (principalId, roleId) = await SetupPrincipalAndRole("grant-resource");
        var request = new GrantRoleRequest
        {
            RoleId = roleId,
            ResourcePath = "buckets/test-bucket-123"
        };

        // Act
        var response = await Client.PostAsJsonAsync($"/iam/v1/principals/{principalId}/roles", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<RoleBindingResponse>();
        Assert.NotNull(result);
        Assert.Equal("buckets/test-bucket-123", result.ResourcePath);
    }

    [Fact]
    public async Task GrantRole_WithExpiration_ReturnsOk()
    {
        await CleanDatabaseAsync();

        // Arrange
        var (principalId, roleId) = await SetupPrincipalAndRole("grant-expiration");
        var expiresAt = DateTime.UtcNow.AddDays(7);
        var request = new GrantRoleRequest
        {
            RoleId = roleId,
            ExpiresAt = expiresAt
        };

        // Act
        var response = await Client.PostAsJsonAsync($"/iam/v1/principals/{principalId}/roles", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<RoleBindingResponse>();
        Assert.NotNull(result);
        Assert.NotNull(result.ExpiresAt);
        Assert.True(result.ExpiresAt.Value > DateTime.UtcNow);
    }

    [Fact]
    public async Task GrantRole_NonExistentRole_ReturnsConflict()
    {
        await CleanDatabaseAsync();

        // Arrange
        var (principalId, _) = await SetupPrincipalAndRole("grant-invalid-role");
        var request = new GrantRoleRequest
        {
            RoleId = "nonexistent-service/nonexistent-role"
        };

        // Act
        var response = await Client.PostAsJsonAsync($"/iam/v1/principals/{principalId}/roles", request);

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task RevokeRole_ExistingBinding_ReturnsNoContent()
    {
        await CleanDatabaseAsync();

        // Arrange
        var (principalId, roleId) = await SetupPrincipalAndRole("revoke-valid");
        var grantRequest = new GrantRoleRequest
        {
            RoleId = roleId
        };
        var grantResponse = await Client.PostAsJsonAsync($"/iam/v1/principals/{principalId}/roles", grantRequest);
        var binding = await grantResponse.Content.ReadFromJsonAsync<RoleBindingResponse>();

        // Act
        var response = await Client.DeleteAsync($"/iam/v1/principals/{principalId}/roles/{binding!.BindingId}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task RevokeRole_NonExistentBinding_ReturnsNotFound()
    {
        await CleanDatabaseAsync();

        // Arrange
        var (principalId, _) = await SetupPrincipalAndRole("revoke-nonexistent");
        var nonExistentId = Guid.NewGuid();

        // Act
        var response = await Client.DeleteAsync($"/iam/v1/principals/{principalId}/roles/{nonExistentId}");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetBindings_ReturnsAllBindings()
    {
        await CleanDatabaseAsync();

        // Arrange
        var (principalId, roleId) = await SetupPrincipalAndRole("get-bindings");
        var grantRequest = new GrantRoleRequest
        {
            RoleId = roleId
        };
        await Client.PostAsJsonAsync($"/iam/v1/principals/{principalId}/roles", grantRequest);

        // Act
        var response = await Client.GetAsync($"/iam/v1/principals/{principalId}/roles");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<List<RoleBindingResponse>>();
        Assert.NotNull(result);
        Assert.True(result.Count >= 1);
        Assert.All(result, b => Assert.Equal(principalId, b.PrincipalId));
    }

    [Fact]
    public async Task GrantRole_DuplicateBinding_ReturnsConflict()
    {
        await CleanDatabaseAsync();

        // Arrange
        var (principalId, roleId) = await SetupPrincipalAndRole("duplicate-binding");
        var grantRequest = new GrantRoleRequest
        {
            RoleId = roleId
        };

        // Act - First grant
        await Client.PostAsJsonAsync($"/iam/v1/principals/{principalId}/roles", grantRequest);

        // Act - Try duplicate grant
        var response = await Client.PostAsJsonAsync($"/iam/v1/principals/{principalId}/roles", grantRequest);

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task MultipleBindings_DifferentRoles_AllCreatedSuccessfully()
    {
        await CleanDatabaseAsync();

        // Arrange
        var principalRequest = new CreateServiceAccountRequest
        {
            Name = "multi-binding-account",
            Description = "Account for multiple bindings"
        };
        var principalResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", principalRequest);
        var principal = await principalResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        // Create two roles
        var serviceName = "multi-binding-service";
        var permRequest = new RegisterPermissionsRequest
        {
            ServiceName = serviceName,
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = $"{serviceName}.data.read", Description = "Read" },
                new() { PermissionId = $"{serviceName}.data.write", Description = "Write" }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/permissions/register", permRequest);

        var roleRequest = new RegisterRolesRequest
        {
            ServiceName = serviceName,
            Roles = new List<RoleDto>
            {
                new()
                {
                    RoleId = $"roles.{serviceName}.reader",
                    Description = "Reader",
                    PermissionIds = new List<string> { $"{serviceName}.data.read" },
                    IsCustom = false
                },
                new()
                {
                    RoleId = $"roles.{serviceName}.writer",
                    Description = "Writer",
                    PermissionIds = new List<string> { $"{serviceName}.data.write" },
                    IsCustom = false
                }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/roles/register", roleRequest);

        // Act - Grant both roles
        var grant1 = await Client.PostAsJsonAsync($"/iam/v1/principals/{principal!.PrincipalId}/roles", new GrantRoleRequest
        {
            RoleId = $"roles.{serviceName}.reader"
        });
        var grant2 = await Client.PostAsJsonAsync($"/iam/v1/principals/{principal.PrincipalId}/roles", new GrantRoleRequest
        {
            RoleId = $"roles.{serviceName}.writer"
        });

        // Assert
        Assert.Equal(HttpStatusCode.OK, grant1.StatusCode);
        Assert.Equal(HttpStatusCode.OK, grant2.StatusCode);

        var bindings = await Client.GetAsync($"/iam/v1/principals/{principal.PrincipalId}/roles");
        var result = await bindings.Content.ReadFromJsonAsync<List<RoleBindingResponse>>();
        Assert.NotNull(result);
        Assert.True(result.Count >= 2);
    }
}
