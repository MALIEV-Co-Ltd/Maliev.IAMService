using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Application.Services;
using Maliev.IAMService.Tests.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Integration tests for Roles Controller.
/// Tests custom role CRUD operations and permission management via public APIs.
/// Registration tests moved to PermissionRegistrationRequestConsumerTests (RabbitMQ-based).
/// </summary>
public class RolesControllerTests : BaseIntegrationTest
{
    public RolesControllerTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    /// <summary>
    /// Helper method to register test permissions directly via service layer.
    /// Used to seed test data for role tests.
    /// </summary>
    private async Task<List<string>> RegisterTestPermissions(string serviceName)
    {
        using var scope = Factory.Services.CreateScope();
        var permissionService = scope.ServiceProvider.GetRequiredService<IPermissionService>();

        var permRequest = new RegisterPermissionsRequest
        {
            ServiceName = serviceName,
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = $"{serviceName}.data.read", Description = "Read permission" },
                new() { PermissionId = $"{serviceName}.data.write", Description = "Write permission" }
            }
        };

        await permissionService.RegisterPermissionsAsync(permRequest);
        return new List<string> { $"{serviceName}.data.read", $"{serviceName}.data.write" };
    }

    /// <summary>
    /// Helper method to register test roles directly via service layer.
    /// Used to seed test data for role CRUD tests.
    /// </summary>
    private async Task RegisterTestRoles(string serviceName, List<string> permissions)
    {
        using var scope = Factory.Services.CreateScope();
        var roleService = scope.ServiceProvider.GetRequiredService<IRoleService>();

        var roleRequest = new RegisterRolesRequest
        {
            ServiceName = serviceName,
            Roles = new List<RoleDto>
            {
                new()
                {
                    RoleId = $"roles.{serviceName}.admin",
                    Description = "Admin role",
                    PermissionIds = permissions,
                    IsCustom = false
                }
            }
        };

        await roleService.RegisterRolesAsync(roleRequest);
    }

    // REMOVED: RegisterRoles HTTP endpoint tests - replaced by PermissionRegistrationRequestConsumerTests
    // Registration now happens via RabbitMQ messages, not HTTP endpoints

    [Fact]
    public async Task CreateCustomRole_ValidRequest_ReturnsCreated()
    {
        await CleanDatabaseAsync();

        // Arrange
        var serviceName = "custom-role-service";
        var permissions = await RegisterTestPermissions(serviceName);

        var request = new CreateCustomRoleRequest
        {
            RoleId = $"roles.{serviceName}.custom-role",
            ServiceName = serviceName,
            Description = "Custom role for testing",
            PermissionIds = permissions
        };

        // Act
        var response = await Client.PostAsJsonAsync("/iam/v1/roles", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<RoleResponse>();
        Assert.NotNull(result);
        Assert.Equal(request.RoleId, result.RoleId);
        Assert.True(result.IsCustom);
    }

    [Fact]
    public async Task UpdateRole_AddPermissions_ReturnsUpdatedRole()
    {
        await CleanDatabaseAsync();

        // Arrange
        var serviceName = "update-role-service";
        var initialPermissions = await RegisterTestPermissions(serviceName);

        // Register additional permission
        var additionalPerm = new RegisterPermissionsRequest
        {
            ServiceName = serviceName,
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = $"{serviceName}.data.delete", Description = "Delete permission" }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/permissions/register", additionalPerm);

        // Create custom role
        var createRequest = new CreateCustomRoleRequest
        {
            RoleId = $"roles.{serviceName}.updatable-role",
            ServiceName = serviceName,
            Description = "Role to update",
            PermissionIds = new List<string> { initialPermissions[0] }
        };
        await Client.PostAsJsonAsync("/iam/v1/roles", createRequest);

        // Act - Update role
        var updateRequest = new UpdateRoleRequest
        {
            Description = "Updated description",
            AddPermissionIds = new List<string> { $"{serviceName}.data.delete" },
            RemovePermissionIds = null
        };
        // Don't URL encode since we use {**roleId} catch-all route
        var response = await Client.PutAsJsonAsync($"/iam/v1/roles/{createRequest.RoleId}", updateRequest);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<RoleResponse>();
        Assert.NotNull(result);
        Assert.Contains($"{serviceName}.data.delete", result.PermissionIds);
    }

    [Fact]
    public async Task UpdateRole_RemovePermissions_ReturnsUpdatedRole()
    {
        await CleanDatabaseAsync();

        // Arrange
        var serviceName = "remove-perm-service";
        var permissions = await RegisterTestPermissions(serviceName);

        var createRequest = new CreateCustomRoleRequest
        {
            RoleId = $"roles.{serviceName}.removable-role",
            ServiceName = serviceName,
            Description = "Role with removable permissions",
            PermissionIds = permissions
        };
        await Client.PostAsJsonAsync("/iam/v1/roles", createRequest);

        // Act - Remove a permission
        var updateRequest = new UpdateRoleRequest
        {
            RemovePermissionIds = new List<string> { permissions[0] }
        };
        // Don't URL encode since we use {**roleId} catch-all route
        var response = await Client.PutAsJsonAsync($"/iam/v1/roles/{createRequest.RoleId}", updateRequest);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<RoleResponse>();
        Assert.NotNull(result);
        Assert.DoesNotContain(permissions[0], result.PermissionIds);
        Assert.Contains(permissions[1], result.PermissionIds);
    }

    [Fact]
    public async Task UpdateRole_PredefinedRole_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        // Arrange
        var serviceName = "predefined-service";
        var permissions = await RegisterTestPermissions(serviceName);

        var registerRequest = new RegisterRolesRequest
        {
            ServiceName = serviceName,
            Roles = new List<RoleDto>
            {
                new()
                {
                    RoleId = $"roles.{serviceName}.predefined-role",
                    Description = "Predefined role",
                    PermissionIds = permissions,
                    IsCustom = false
                }
            }
        };
        var registerResponse = await Client.PostAsJsonAsync("/iam/v1/roles/register", registerRequest);
        Assert.Equal(HttpStatusCode.OK, registerResponse.StatusCode); // Ensure role was registered

        // Act - Try to update predefined role
        var updateRequest = new UpdateRoleRequest
        {
            Description = "Should not work"
        };
        // Don't URL encode since we use {**roleId} catch-all route
        var response = await Client.PutAsJsonAsync($"/iam/v1/roles/roles.{serviceName}.predefined-role", updateRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task DeleteRole_CustomRoleWithoutBindings_ReturnsNoContent()
    {
        await CleanDatabaseAsync();

        // Arrange
        var serviceName = "delete-service";
        var permissions = await RegisterTestPermissions(serviceName);

        var createRequest = new CreateCustomRoleRequest
        {
            RoleId = $"roles.{serviceName}.deletable-role",
            ServiceName = serviceName,
            Description = "Role to delete",
            PermissionIds = permissions
        };
        await Client.PostAsJsonAsync("/iam/v1/roles", createRequest);

        // Act
        // Don't URL encode since we use {**roleId} catch-all route
        var response = await Client.DeleteAsync($"/iam/v1/roles/{createRequest.RoleId}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task DeleteRole_PredefinedRole_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        // Arrange
        var serviceName = "delete-predefined-service";
        var permissions = await RegisterTestPermissions(serviceName);

        var registerRequest = new RegisterRolesRequest
        {
            ServiceName = serviceName,
            Roles = new List<RoleDto>
            {
                new()
                {
                    RoleId = $"roles.{serviceName}.system-role",
                    Description = "System role",
                    PermissionIds = permissions,
                    IsCustom = false
                }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/roles/register", registerRequest);

        // Act
        var response = await Client.DeleteAsync($"/iam/v1/roles/{Uri.EscapeDataString($"roles.{serviceName}.system-role")}");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task GetAllRoles_ReturnsAllRegistered()
    {
        await CleanDatabaseAsync();

        // Arrange
        var serviceName = "getall-roles-service";
        var permissions = await RegisterTestPermissions(serviceName);

        var registerRequest = new RegisterRolesRequest
        {
            ServiceName = serviceName,
            Roles = new List<RoleDto>
            {
                new()
                {
                    RoleId = $"roles.{serviceName}.role1",
                    Description = "Role 1",
                    PermissionIds = permissions,
                    IsCustom = false
                }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/roles/register", registerRequest);

        // Act
        var response = await Client.GetAsync("/iam/v1/roles");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<List<RoleResponse>>();
        Assert.NotNull(result);
        Assert.True(result.Count >= 1);
    }

    [Fact]
    public async Task GetRolesByService_ReturnsOnlyMatchingService()
    {
        await CleanDatabaseAsync();

        // Arrange
        var serviceName = "specific-service";
        var permissions = await RegisterTestPermissions(serviceName);

        var registerRequest = new RegisterRolesRequest
        {
            ServiceName = serviceName,
            Roles = new List<RoleDto>
            {
                new()
                {
                    RoleId = $"roles.{serviceName}.specific-role",
                    Description = "Specific role",
                    PermissionIds = permissions,
                    IsCustom = false
                }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/roles/register", registerRequest);

        // Act
        var response = await Client.GetAsync($"/iam/v1/roles?serviceName={serviceName}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<List<RoleResponse>>();
        Assert.NotNull(result);
        Assert.All(result, r => Assert.Equal(serviceName, r.ServiceName));
    }

    [Fact]
    public async Task GetRoleById_ExistingRole_ReturnsRole()
    {
        await CleanDatabaseAsync();

        // Arrange
        var serviceName = "getbyid-service";
        var permissions = await RegisterTestPermissions(serviceName);

        var createRequest = new CreateCustomRoleRequest
        {
            RoleId = $"roles.{serviceName}.getbyid-role",
            ServiceName = serviceName,
            Description = "Role for GetById test",
            PermissionIds = permissions
        };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/roles", createRequest);
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode); // Ensure role was created

        // Act
        // Don't URL encode since we use {**roleId} catch-all route
        var response = await Client.GetAsync($"/iam/v1/roles/{createRequest.RoleId}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<RoleResponse>();
        Assert.NotNull(result);
        Assert.Equal(createRequest.RoleId, result.RoleId);
    }

    [Fact]
    public async Task GetRoleById_NonExistent_ReturnsNotFound()
    {
        await CleanDatabaseAsync();

        // Arrange
        var nonExistentId = "roles.nonexistent-service.nonexistent-role";

        // Act
        var response = await Client.GetAsync($"/iam/v1/roles/{Uri.EscapeDataString(nonExistentId)}");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
