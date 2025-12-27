using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using Maliev.IAMService.Tests.Testing;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Integration tests for Permissions Controller.
/// Tests permission registration, retrieval, and filtering by service.
/// </summary>

public class PermissionsControllerTests : BaseIntegrationTest
{




    [Fact]
    public async Task RegisterPermissions_ValidRequest_ReturnsOk()
    {
        await CleanDatabaseAsync();

        // Arrange
        var request = new RegisterPermissionsRequest
        {
            ServiceName = "test-service",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = "test-service.data.read", Description = "Read permission" },
                new() { PermissionId = "test-service.data.write", Description = "Write permission" },
                new() { PermissionId = "test-service.data.delete", Description = "Delete permission" }
            }
        };

        // Act
        var response = await Client.PostAsJsonAsync("/iam/v1/permissions/register", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<List<PermissionResponse>>();
        Assert.NotNull(result);
        Assert.Equal(3, result.Count);
        Assert.All(result, p => Assert.Equal("test-service", p.ServiceName));
    }

    [Fact]
    public async Task RegisterPermissions_InvalidFormat_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        // Arrange
        var request = new RegisterPermissionsRequest
        {
            ServiceName = "test-service",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = "invalid-format", Description = "Invalid permission" }
            }
        };

        // Act
        var response = await Client.PostAsJsonAsync("/iam/v1/permissions/register", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RegisterPermissions_DuplicatePermissions_SkipsDuplicates()
    {
        await CleanDatabaseAsync();

        // Arrange
        var request = new RegisterPermissionsRequest
        {
            ServiceName = "duplicate-service",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = "duplicate-service.data.read", Description = "Read permission" }
            }
        };

        // Act - Register first time
        await Client.PostAsJsonAsync("/iam/v1/permissions/register", request);

        // Act - Register again
        var response = await Client.PostAsJsonAsync("/iam/v1/permissions/register", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<List<PermissionResponse>>();
        Assert.NotNull(result);
        Assert.Single(result);
    }

    [Fact]
    public async Task GetAllPermissions_ReturnsAllRegistered()
    {
        await CleanDatabaseAsync();

        // Arrange - Register some permissions
        var request = new RegisterPermissionsRequest
        {
            ServiceName = "getall-service",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = "getall-service.resource.action1", Description = "Action 1" },
                new() { PermissionId = "getall-service.resource.action2", Description = "Action 2" }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/permissions/register", request);

        // Act
        var response = await Client.GetAsync("/iam/v1/permissions");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<List<PermissionResponse>>();
        Assert.NotNull(result);
        Assert.True(result.Count >= 2);
    }

    [Fact]
    public async Task GetPermissionsByService_ReturnsOnlyMatchingService()
    {
        await CleanDatabaseAsync();

        // Arrange
        var serviceName = "filtered-service";
        var request = new RegisterPermissionsRequest
        {
            ServiceName = serviceName,
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = $"{serviceName}.data.perm1", Description = "Permission 1" },
                new() { PermissionId = $"{serviceName}.data.perm2", Description = "Permission 2" }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/permissions/register", request);

        // Act
        var response = await Client.GetAsync($"/iam/v1/permissions?serviceName={serviceName}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<List<PermissionResponse>>();
        Assert.NotNull(result);
        Assert.True(result.Count >= 2);
        Assert.All(result, p => Assert.Equal(serviceName, p.ServiceName));
    }

    [Fact]
    public async Task GetPermissionById_ExistingPermission_ReturnsPermission()
    {
        await CleanDatabaseAsync();

        // Arrange
        var permissionId = "byid-service.resource.test-permission";
        var request = new RegisterPermissionsRequest
        {
            ServiceName = "byid-service",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = permissionId, Description = "Test permission for GetById" }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/permissions/register", request);

        // Act
        var response = await Client.GetAsync($"/iam/v1/permissions/{Uri.EscapeDataString(permissionId)}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<PermissionResponse>();
        Assert.NotNull(result);
        Assert.Equal(permissionId, result.PermissionId);
    }

    [Fact]
    public async Task GetPermissionById_NonExistent_ReturnsNotFound()
    {
        await CleanDatabaseAsync();

        // Arrange
        var nonExistentId = "nonexistent-service.resource.nonexistent-permission";

        // Act
        var response = await Client.GetAsync($"/iam/v1/permissions/{Uri.EscapeDataString(nonExistentId)}");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task RegisterPermissions_EmptyServiceName_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        // Arrange
        var request = new RegisterPermissionsRequest
        {
            ServiceName = "",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = "test.data.perm", Description = "Test" }
            }
        };

        // Act
        var response = await Client.PostAsJsonAsync("/iam/v1/permissions/register", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RegisterPermissions_MultipleServices_CorrectlyAssociated()
    {
        await CleanDatabaseAsync();

        // Arrange
        var request1 = new RegisterPermissionsRequest
        {
            ServiceName = "service-a",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = "service-a.data.read", Description = "Service A Read" }
            }
        };
        var request2 = new RegisterPermissionsRequest
        {
            ServiceName = "service-b",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = "service-b.data.read", Description = "Service B Read" }
            }
        };

        // Act
        await Client.PostAsJsonAsync("/iam/v1/permissions/register", request1);
        await Client.PostAsJsonAsync("/iam/v1/permissions/register", request2);

        var responseA = await Client.GetAsync("/iam/v1/permissions?serviceName=service-a");
        var responseB = await Client.GetAsync("/iam/v1/permissions?serviceName=service-b");

        // Assert
        var resultA = await responseA.Content.ReadFromJsonAsync<List<PermissionResponse>>();
        var resultB = await responseB.Content.ReadFromJsonAsync<List<PermissionResponse>>();

        Assert.NotNull(resultA);
        Assert.NotNull(resultB);
        Assert.All(resultA, p => Assert.Equal("service-a", p.ServiceName));
        Assert.All(resultB, p => Assert.Equal("service-b", p.ServiceName));
    }
}
