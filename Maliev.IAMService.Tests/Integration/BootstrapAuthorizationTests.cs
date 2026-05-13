using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Tests.Testing;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Regression tests for IAM bootstrap authorization boundaries.
/// </summary>
public class BootstrapAuthorizationTests : BaseIntegrationTest
{
    public BootstrapAuthorizationTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task AnonymousBootstrapWindow_PrivilegedIamEndpoints_ReturnUnauthorized()
    {
        await CleanDatabaseAsync();
        using var anonymousClient = Factory.CreateClient();

        var principalId = Guid.NewGuid();
        var bindingId = Guid.NewGuid();

        var grantResponse = await anonymousClient.PostAsJsonAsync(
            $"/iam/v1/principals/{principalId}/roles",
            new { roleId = "roles.platform.owner" });
        Assert.Equal(HttpStatusCode.Unauthorized, grantResponse.StatusCode);

        var revokeResponse = await anonymousClient.DeleteAsync(
            $"/iam/v1/principals/{principalId}/roles/{bindingId}");
        Assert.Equal(HttpStatusCode.Unauthorized, revokeResponse.StatusCode);

        var bindingsResponse = await anonymousClient.GetAsync(
            $"/iam/v1/principals/{principalId}/roles");
        Assert.Equal(HttpStatusCode.Unauthorized, bindingsResponse.StatusCode);

        var principalsResponse = await anonymousClient.GetAsync("/iam/v1/principals");
        Assert.Equal(HttpStatusCode.Unauthorized, principalsResponse.StatusCode);

        var rolesResponse = await anonymousClient.GetAsync("/iam/v1/roles");
        Assert.Equal(HttpStatusCode.Unauthorized, rolesResponse.StatusCode);

        var permissionsResponse = await anonymousClient.GetAsync("/iam/v1/permissions");
        Assert.Equal(HttpStatusCode.Unauthorized, permissionsResponse.StatusCode);

        var resolveResponse = await anonymousClient.PostAsJsonAsync(
            "/iam/v1/auth/resolve-permissions",
            new { principalId = principalId.ToString() });
        Assert.Equal(HttpStatusCode.Unauthorized, resolveResponse.StatusCode);

        var checkResponse = await anonymousClient.PostAsJsonAsync(
            "/iam/v1/auth/check-permission",
            new
            {
                principalId = principalId.ToString(),
                permissionId = "iam.roles.read"
            });
        Assert.Equal(HttpStatusCode.Unauthorized, checkResponse.StatusCode);
    }

    [Fact]
    public async Task BootstrapStatus_RemainsAnonymous()
    {
        await CleanDatabaseAsync();
        using var anonymousClient = Factory.CreateClient();

        var response = await anonymousClient.GetAsync("/iam/v1/principals/bootstrap/status");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
