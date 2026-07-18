using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Tests.Testing;

namespace Maliev.IAMService.Tests.Integration;

public class ServiceAccountsControllerIntegrationTests : BaseIntegrationTest
{
    public ServiceAccountsControllerIntegrationTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task CreateServiceAccount_ValidRequest_ReturnsCreated()
    {
        await CleanDatabaseAsync();

        var request = new CreateServiceAccountRequest
        {
            Name = "test-service-account",
            Description = "Test service account"
        };

        var response = await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<ServiceAccountResponse>();
        Assert.NotNull(result);
        Assert.NotEqual(Guid.Empty, result.PrincipalId);
        Assert.Equal("test-service-account", result.Name);
    }

    [Fact]
    public async Task CreateServiceAccount_DuplicateName_ReturnsConflict()
    {
        await CleanDatabaseAsync();

        var request = new CreateServiceAccountRequest
        {
            Name = "duplicate-name-account",
            Description = "Test"
        };

        await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);
        var response = await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task GetServiceAccounts_ReturnsList()
    {
        await CleanDatabaseAsync();

        var createRequest = new CreateServiceAccountRequest { Name = "list-test-1" };
        var createRequest2 = new CreateServiceAccountRequest { Name = "list-test-2" };
        await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest2);

        var response = await Client.GetAsync("/iam/v1/service-accounts");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<List<ServiceAccountResponse>>();
        Assert.NotNull(result);
        Assert.True(result.Count >= 2);
    }

    [Fact]
    public async Task GetServiceAccountById_Existing_ReturnsOk()
    {
        await CleanDatabaseAsync();

        var createRequest = new CreateServiceAccountRequest { Name = "get-by-id-test" };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        var created = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        var response = await Client.GetAsync($"/iam/v1/principals/{created!.PrincipalId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GetServiceAccountById_NonExisting_ReturnsNotFound()
    {
        await CleanDatabaseAsync();

        var response = await Client.GetAsync($"/iam/v1/service-accounts/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task RotateApiKey_Existing_ReturnsNewKey()
    {
        await CleanDatabaseAsync();

        var createRequest = new CreateServiceAccountRequest { Name = "rotate-key-test" };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        var created = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        var response = await Client.PostAsync($"/iam/v1/service-accounts/{created!.PrincipalId}/rotate-key", null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<RotateApiKeyResponse>();
        Assert.NotNull(result);
        Assert.NotEmpty(result.NewApiKey);
    }

    [Fact]
    public async Task RotateApiKey_NonExisting_ReturnsNotFound()
    {
        await CleanDatabaseAsync();

        var response = await Client.PostAsync($"/iam/v1/service-accounts/{Guid.NewGuid()}/rotate-key", null);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetEffectivePermissions_WithoutRoles_ReturnsEmptyList()
    {
        await CleanDatabaseAsync();

        var createRequest = new CreateServiceAccountRequest { Name = "no-perms-test" };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        var created = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        var response = await Client.GetAsync($"/iam/v1/service-accounts/{created!.PrincipalId}/effective-permissions");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<EffectivePermissionsResponse>();
        Assert.NotNull(result);
    }

    [Fact]
    public async Task GetEffectivePermissions_WithResourceScope_ReturnsOk()
    {
        await CleanDatabaseAsync();

        var createRequest = new CreateServiceAccountRequest { Name = "resource-scope-test" };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        var created = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        var response = await Client.GetAsync($"/iam/v1/service-accounts/{created!.PrincipalId}/effective-permissions?resourceType=bucket&resourceId=test-123");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
