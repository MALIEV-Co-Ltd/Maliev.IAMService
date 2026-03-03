using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Tests.Testing;

namespace Maliev.IAMService.Tests.Integration;

public class RolesControllerExtendedTests : BaseIntegrationTest
{
    public RolesControllerExtendedTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    private async Task<string> SetupServiceAndRole(string testName)
    {
        var serviceName = $"role-ext-test-{testName}";
        
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
                    RoleId = $"roles.{serviceName}.admin",
                    Description = "Admin",
                    PermissionIds = new List<string> { $"{serviceName}.data.read", $"{serviceName}.data.write" }
                }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/roles/register", roleRequest);

        return $"roles.{serviceName}.admin";
    }

    [Fact]
    public async Task CreateCustomRole_ValidRequest_ReturnsCreated()
    {
        await CleanDatabaseAsync();

        var request = new CreateCustomRoleRequest
        {
            RoleId = "roles.custom.test",
            ServiceName = "custom",
            Description = "Custom role",
            PermissionIds = new List<string>()
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/roles", request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task DeleteRole_ExistingRole_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        var roleId = await SetupServiceAndRole("delete-test");

        var response = await Client.DeleteAsync($"/iam/v1/roles/{Uri.EscapeDataString(roleId)}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task DeleteRole_NonExistentRole_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        var response = await Client.DeleteAsync($"/iam/v1/roles/{Uri.EscapeDataString("roles.nonexistent.role")}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RegisterRoles_MultipleRoles_ReturnsOk()
    {
        await CleanDatabaseAsync();

        var serviceName = "multi-role-test";
        var request = new RegisterRolesRequest
        {
            ServiceName = serviceName,
            Roles = new List<RoleDto>
            {
                new() { RoleId = $"roles.{serviceName}.reader", Description = "Reader", PermissionIds = new List<string>() },
                new() { RoleId = $"roles.{serviceName}.writer", Description = "Writer", PermissionIds = new List<string>() },
                new() { RoleId = $"roles.{serviceName}.admin", Description = "Admin", PermissionIds = new List<string>() }
            }
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/roles/register", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
