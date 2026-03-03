using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Tests.Testing;

namespace Maliev.IAMService.Tests.Integration;

public class TokenServiceIntegrationTests : BaseIntegrationTest
{
    public TokenServiceIntegrationTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task IssueToken_WithValidServiceAccount_ReturnsToken()
    {
        await CleanDatabaseAsync();

        var createRequest = new CreateServiceAccountRequest
        {
            Name = "token-test-account",
            Description = "Test account for token"
        };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        var created = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        var tokenRequest = new IssueTokenRequest
        {
            PrincipalId = created!.PrincipalId.ToString()
        };
        var tokenResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token", tokenRequest);

        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        var tokenResult = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(tokenResult);
        Assert.NotEmpty(tokenResult.AccessToken);
        Assert.NotEmpty(tokenResult.RefreshToken);
    }

    [Fact]
    public async Task IssueToken_WithResourcePath_ReturnsToken()
    {
        await CleanDatabaseAsync();

        var createRequest = new CreateServiceAccountRequest
        {
            Name = "token-resource-account",
            Description = "Test"
        };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        var created = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        var tokenRequest = new IssueTokenRequest
        {
            PrincipalId = created!.PrincipalId.ToString(),
            ResourcePath = "projects/my-project"
        };
        var tokenResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token", tokenRequest);

        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
    }

    [Fact]
    public async Task IssueToken_WithInvalidPrincipal_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        var tokenRequest = new IssueTokenRequest
        {
            PrincipalId = Guid.NewGuid().ToString()
        };
        var tokenResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token", tokenRequest);

        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
    }

    [Fact]
    public async Task RefreshToken_WithValidRefreshToken_ReturnsNewToken()
    {
        await CleanDatabaseAsync();

        var createRequest = new CreateServiceAccountRequest
        {
            Name = "refresh-test-account",
            Description = "Test"
        };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        var created = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        var issueRequest = new IssueTokenRequest
        {
            PrincipalId = created!.PrincipalId.ToString()
        };
        var issueResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token", issueRequest);
        var issueResult = await issueResponse.Content.ReadFromJsonAsync<TokenResponse>();

        var refreshRequest = new RefreshTokenRequest
        {
            RefreshToken = issueResult!.RefreshToken
        };
        var refreshResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token/refresh", refreshRequest);

        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);
        var refreshResult = await refreshResponse.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(refreshResult);
        Assert.NotEmpty(refreshResult.AccessToken);
        Assert.NotEqual(issueResult.AccessToken, refreshResult.AccessToken);
    }

    [Fact]
    public async Task RefreshToken_WithInvalidRefreshToken_ReturnsUnauthorized()
    {
        await CleanDatabaseAsync();

        var refreshRequest = new RefreshTokenRequest
        {
            RefreshToken = "invalid-refresh-token"
        };
        var refreshResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token/refresh", refreshRequest);

        Assert.Equal(HttpStatusCode.Unauthorized, refreshResponse.StatusCode);
    }

    [Fact]
    public async Task RefreshToken_WithExpiredRefreshToken_ReturnsUnauthorized()
    {
        await CleanDatabaseAsync();

        var createRequest = new CreateServiceAccountRequest
        {
            Name = "expired-token-account",
            Description = "Test"
        };
        var createResponse = await Client.PostAsJsonAsync("/iam/v1/service-accounts", createRequest);
        var created = await createResponse.Content.ReadFromJsonAsync<ServiceAccountResponse>();

        var issueRequest = new IssueTokenRequest
        {
            PrincipalId = created!.PrincipalId.ToString()
        };
        var issueResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token", issueRequest);
        var issueResult = await issueResponse.Content.ReadFromJsonAsync<TokenResponse>();

        var refreshRequest = new RefreshTokenRequest
        {
            RefreshToken = issueResult!.RefreshToken
        };

        await Client.PostAsJsonAsync("/iam/v1/auth/token/refresh", refreshRequest);
        var secondRefreshResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token/refresh", refreshRequest);

        Assert.Equal(HttpStatusCode.Unauthorized, secondRefreshResponse.StatusCode);
    }

    [Fact]
    public async Task GetJwks_ReturnsValidJwks()
    {
        await CleanDatabaseAsync();

        var response = await Client.GetAsync("/iam/v1/auth/.well-known/jwks.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("keys", content);
        Assert.Contains("kty", content);
    }

    [Fact]
    public async Task GetJwks_ContainsRsaKey()
    {
        await CleanDatabaseAsync();

        var response = await Client.GetAsync("/iam/v1/auth/.well-known/jwks.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("RSA", content);
    }
}
