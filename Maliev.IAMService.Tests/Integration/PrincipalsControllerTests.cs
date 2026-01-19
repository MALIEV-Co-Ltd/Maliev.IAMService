using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using Maliev.IAMService.Tests.Testing;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Integration tests for Principals (Service Accounts) Controller.
/// Tests service account creation, API key rotation, and permission queries.
/// </summary>

public class PrincipalsControllerTests : BaseIntegrationTest
{
    public PrincipalsControllerTests(TestWebApplicationFactory factory) : base(factory)
    {
    }





    [Fact]
    public async Task CreateServiceAccount_ValidRequest_ReturnsCreatedWithApiKey()
    {
        await CleanDatabaseAsync();

        // Arrange
        var request = new CreateServiceAccountRequest
        {
            Name = "test-service-account",
            Description = "Test service account for integration testing"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<ServiceAccountResponse>();
        Assert.NotNull(result);
        Assert.Equal(request.Name, result.Name);
        Assert.NotEqual(Guid.Empty, result.PrincipalId);
        Assert.NotNull(result.ApiKey);
        Assert.NotEmpty(result.ApiKey);
    }

    [Fact]
    public async Task CreateServiceAccount_DuplicateName_ReturnsConflict()
    {
        await CleanDatabaseAsync();

        // Arrange
        var request = new CreateServiceAccountRequest
        {
            Name = "duplicate-test-account",
            Description = "First creation"
        };

        // Act - Create first account
        await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);

        // Act - Try to create duplicate
        var response = await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task GetServiceAccounts_ReturnsAllAccounts()
    {
        await CleanDatabaseAsync();

        // Arrange
        var request1 = new CreateServiceAccountRequest
        {
            Name = "test-account-1",
            Description = "First account"
        };
        var request2 = new CreateServiceAccountRequest
        {
            Name = "test-account-2",
            Description = "Second account"
        };

        await Client.PostAsJsonAsync("/iam/v1/service-accounts", request1);
        await Client.PostAsJsonAsync("/iam/v1/service-accounts", request2);

        // Act
        var response = await Client.GetAsync("/iam/v1/service-accounts");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<List<ServiceAccountResponse>>();
        Assert.NotNull(result);
        Assert.True(result.Count >= 2);
    }

    [Fact]
    public async Task RotateApiKey_ValidAccount_ReturnsNewKey()
    {
        await CleanDatabaseAsync();

        // Arrange - Create service account
        var createRequest = new CreateServiceAccountRequest
        {
            Name = "rotation-test-account",
            Description = "Account for key rotation testing"
        };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        var account = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();
        Assert.NotNull(account);

        var originalKey = account.ApiKey;

        // Act - Rotate the key
        var rotateResponse = await Client.PostAsync($"/iam/v1/service-accounts/{account.PrincipalId}/rotate-key", null);

        // Assert
        Assert.Equal(HttpStatusCode.OK, rotateResponse.StatusCode);
        var rotateResult = await rotateResponse.Content.ReadFromJsonAsync<RotateApiKeyResponse>();
        Assert.NotNull(rotateResult);
        Assert.NotEqual(originalKey, rotateResult.NewApiKey);
        Assert.NotEmpty(rotateResult.NewApiKey);
    }

    [Fact]
    public async Task RotateApiKey_NonExistentAccount_ReturnsNotFound()
    {
        await CleanDatabaseAsync();

        // Arrange
        var nonExistentId = Guid.NewGuid();

        // Act
        var response = await Client.PostAsync($"/iam/v1/service-accounts/{nonExistentId}/rotate-key", null);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetEffectivePermissions_ValidAccount_ReturnsPermissions()
    {
        await CleanDatabaseAsync();

        // Arrange - Create service account
        var createRequest = new CreateServiceAccountRequest
        {
            Name = "permissions-test-account",
            Description = "Account for permission testing"
        };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        var account = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();
        Assert.NotNull(account);

        // Act
        var response = await Client.GetAsync($"/iam/v1/service-accounts/{account.PrincipalId}/effective-permissions");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<EffectivePermissionsResponse>();
        Assert.NotNull(result);
        Assert.NotNull(result.Permissions);
    }

    [Fact]
    public async Task GetEffectivePermissions_WithResourceFilter_ReturnsFilteredPermissions()
    {
        await CleanDatabaseAsync();

        // Arrange
        var createRequest = new CreateServiceAccountRequest
        {
            Name = "filtered-permissions-account",
            Description = "Account for filtered permission testing"
        };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        var account = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();
        Assert.NotNull(account);

        // Act
        var response = await Client.GetAsync(
            $"/iam/v1/service-accounts/{account.PrincipalId}/effective-permissions?resourceType=bucket&resourceId=test-bucket-123");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<EffectivePermissionsResponse>();
        Assert.NotNull(result);
    }

    [Fact]
    public async Task GetEffectivePermissions_NonExistentAccount_ReturnsNotFound()
    {
        await CleanDatabaseAsync();

        // Arrange
        var nonExistentId = Guid.NewGuid();

        // Act
        var response = await Client.GetAsync($"/iam/v1/service-accounts/{nonExistentId}/effective-permissions");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
