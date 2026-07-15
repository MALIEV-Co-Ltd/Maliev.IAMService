using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Tests.Testing;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Verifies the authenticated HTTP boundary for authoritative permission checks.
/// </summary>
public class LivePermissionCheckAuthorizationTests : BaseIntegrationTest
{
    public LivePermissionCheckAuthorizationTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task POST_CheckPermission_LiveCheckWithProductionServiceClaims_ReturnsOk()
    {
        await CleanDatabaseAsync();
        using var client = Factory.CreateLivePermissionCheckServiceClient();

        var response = await client.PostAsJsonAsync("/iam/v1/auth/check-permission", CreateRequest(bypassCache: true));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task POST_CheckPermission_LiveCheckWithProductionServiceClaimsButMissingCredential_ReturnsForbidden()
    {
        await CleanDatabaseAsync();
        using var client = Factory.CreateLivePermissionCheckServiceClient();
        client.DefaultRequestHeaders.Remove("X-Maliev-IAM-Live-Check-Key");

        var response = await client.PostAsJsonAsync("/iam/v1/auth/check-permission", CreateRequest(bypassCache: true));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task POST_CheckPermission_LiveCheckWithProductionServiceClaimsButWrongCredential_ReturnsForbidden()
    {
        await CleanDatabaseAsync();
        using var client = Factory.CreateLivePermissionCheckServiceClient();
        client.DefaultRequestHeaders.Remove("X-Maliev-IAM-Live-Check-Key");
        client.DefaultRequestHeaders.Add("X-Maliev-IAM-Live-Check-Key", "wrong-credential");

        var response = await client.PostAsJsonAsync("/iam/v1/auth/check-permission", CreateRequest(bypassCache: true));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task POST_CheckPermission_LiveCheckWithEmployeeToken_ReturnsProblemDetailsForbidden()
    {
        await CleanDatabaseAsync();
        var token = Factory.CreateTestJwtToken(
            permissions: ["iam.auth.check-permission"]);
        using var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var response = await client.PostAsJsonAsync("/iam/v1/auth/check-permission", CreateRequest(bypassCache: true));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var problem = await response.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal(StatusCodes.Status403Forbidden, problem.Status);
    }

    private static CheckPermissionRequest CreateRequest(bool bypassCache) => new()
    {
        PrincipalId = "00000000-0000-0000-0000-000000000003",
        PermissionId = "employee.reports.view",
        BypassCache = bypassCache
    };
}
