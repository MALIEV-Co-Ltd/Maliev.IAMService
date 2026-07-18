using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Tests.Testing;

namespace Maliev.IAMService.Tests.Integration;

public class ErrorHandlingIntegrationTests : BaseIntegrationTest
{
    public ErrorHandlingIntegrationTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task CreatePrincipal_InvalidEmailFormat_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        var request = new CreatePrincipalRequest
        {
            PrincipalType = "user",
            Email = "not-an-email",
            DisplayName = "Test"
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/principals", request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task CreatePrincipal_MissingRequiredFields_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        var request = new CreatePrincipalRequest
        {
            PrincipalType = "user"
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/principals", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RegisterPermissions_InvalidPermissionFormat_ReturnsOk()
    {
        await CleanDatabaseAsync();

        var request = new RegisterPermissionsRequest
        {
            ServiceName = "test-service",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = "InvalidPermission", Description = "Test" }
            }
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/permissions/register", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task RegisterRoles_InvalidRoleId_ReturnsOk()
    {
        await CleanDatabaseAsync();

        var request = new RegisterRolesRequest
        {
            ServiceName = "test-service",
            Roles = new List<RoleDto>
            {
                new() { RoleId = "Invalid_Role_Id", Description = "Test", PermissionIds = new List<string>() }
            }
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/roles/register", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CreateCustomRole_EmptyRoleId_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        var request = new CreateCustomRoleRequest
        {
            RoleId = "",
            ServiceName = "test",
            Description = "Test",
            PermissionIds = new List<string>()
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/roles", request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task GrantRole_InvalidPrincipalId_ReturnsConflict()
    {
        await CleanDatabaseAsync();

        var request = new GrantRoleRequest { RoleId = "roles.test.admin" };

        var response = await Client.PostAsJsonAsync($"/iam/v1/principals/{Guid.NewGuid()}/roles", request);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task GetPrincipalById_NonExistent_ReturnsNotFound()
    {
        await CleanDatabaseAsync();

        var response = await Client.GetAsync($"/iam/v1/principals/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task DeletePrincipal_NonExistent_ReturnsNoContent()
    {
        await CleanDatabaseAsync();

        var response = await Client.DeleteAsync($"/iam/v1/principals/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task UpdateRole_NonExistent_ReturnsNotFound()
    {
        await CleanDatabaseAsync();

        var request = new UpdateRoleRequest { Description = "Updated" };

        var response = await Client.PutAsJsonAsync("/iam/v1/roles/non.existent.role", request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task IssueToken_MissingPrincipalId_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        var request = new IssueTokenRequest
        {
            PrincipalId = ""
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RefreshToken_MissingRefreshToken_ReturnsUnauthorized()
    {
        await CleanDatabaseAsync();

        var request = new RefreshTokenRequest
        {
            RefreshToken = ""
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token/refresh", request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ResolvePermissions_InvalidPrincipalId_ReturnsOkWithEmptyPermissions()
    {
        await CleanDatabaseAsync();

        var request = new ResolvePermissionsRequest
        {
            PrincipalId = "invalid-guid-format"
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/auth/resolve-permissions", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
