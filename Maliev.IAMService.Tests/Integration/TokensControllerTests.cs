using System.Net;
using System.Net.Http.Json;
using System.IdentityModel.Tokens.Jwt;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Tests.Testing;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Integration tests for Tokens Controller.
/// Tests JWT token issuance, refresh, and JWKS retrieval.
/// </summary>

public class TokensControllerTests : BaseIntegrationTest
{
    public TokensControllerTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    private async Task<Guid> CreateTestPrincipal(string name)

    {
        var request = new CreateServiceAccountRequest
        {
            Name = name,
            Description = $"Test account for {name}"
        };
        var response = await Client.PostAsJsonAsync("/iam/v1/service-accounts", request);
        var result = await response.Content.ReadFromJsonAsync<ServiceAccountResponse>();
        return result!.PrincipalId;
    }

    [Fact]
    public async Task IssueToken_ValidPrincipal_ReturnsValidToken()
    {
        await CleanDatabaseAsync();

        // Arrange
        var principalId = await CreateTestPrincipal("token-test-principal");
        var request = new IssueTokenRequest
        {
            PrincipalId = principalId.ToString()
        };

        // Act
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(result);
        Assert.NotNull(result.AccessToken);
        Assert.NotNull(result.RefreshToken);
        Assert.Equal("Bearer", result.TokenType);
        Assert.True(result.ExpiresIn > 0);
        Assert.True(result.ExpiresAt > DateTime.UtcNow);
    }

    [Fact]
    public async Task IssueToken_ValidJwtStructure_ContainsExpectedClaims()
    {
        await CleanDatabaseAsync();

        // Arrange
        var principalId = await CreateTestPrincipal("jwt-structure-test");
        var request = new IssueTokenRequest
        {
            PrincipalId = principalId.ToString()
        };

        // Act
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token", request);
        var result = await response.Content.ReadFromJsonAsync<TokenResponse>();

        // Assert
        Assert.NotNull(result);
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(result.AccessToken);

        Assert.Contains(jwtToken.Claims, c => c.Type == JwtRegisteredClaimNames.Sub);
        Assert.Contains(jwtToken.Claims, c => c.Type == JwtRegisteredClaimNames.Jti);
        Assert.Contains(jwtToken.Claims, c => c.Type == "principal_id");
        Assert.Contains(jwtToken.Claims, c => c.Type == "principal_type");
    }

    [Fact]
    public async Task IssueToken_WithResourceScope_IncludesResourceClaims()
    {
        await CleanDatabaseAsync();

        // Arrange
        var principalId = await CreateTestPrincipal("resource-scope-test");
        var request = new IssueTokenRequest
        {
            PrincipalId = principalId.ToString(),
            ResourcePath = "buckets/test-bucket-789"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token", request);
        var result = await response.Content.ReadFromJsonAsync<TokenResponse>();

        // Assert
        Assert.NotNull(result);
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(result.AccessToken);

        Assert.Contains(jwtToken.Claims, c => c.Type == "resource_path" && c.Value == "buckets/test-bucket-789");
    }

    [Fact]
    public async Task IssueToken_WithCustomExpiration_ReturnsTokenWithCorrectExpiry()
    {
        await CleanDatabaseAsync();

        // Arrange
        var principalId = await CreateTestPrincipal("custom-expiry-test");
        var request = new IssueTokenRequest
        {
            PrincipalId = principalId.ToString(),
            ExpiresInMinutes = 30
        };

        // Act
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token", request);
        var result = await response.Content.ReadFromJsonAsync<TokenResponse>();

        // Assert
        Assert.NotNull(result);
        Assert.Equal(30 * 60, result.ExpiresIn); // 30 minutes in seconds
        var expiryDiff = result.ExpiresAt - DateTime.UtcNow;
        Assert.True(expiryDiff.TotalMinutes >= 29 && expiryDiff.TotalMinutes <= 31);
    }

    [Fact]
    public async Task IssueToken_NonExistentPrincipal_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();

        // Arrange
        var nonExistentId = Guid.NewGuid();
        var request = new IssueTokenRequest
        {
            PrincipalId = nonExistentId.ToString()
        };

        // Act
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RefreshToken_ValidRefreshToken_ReturnsNewTokenPair()
    {
        await CleanDatabaseAsync();

        // Arrange - Issue initial token
        var principalId = await CreateTestPrincipal("refresh-test-principal");
        var issueRequest = new IssueTokenRequest
        {
            PrincipalId = principalId.ToString()
        };
        var issueResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token", issueRequest);
        var issueResult = await issueResponse.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(issueResult);

        var originalAccessToken = issueResult.AccessToken;
        var originalRefreshToken = issueResult.RefreshToken;

        // Act - Refresh the token
        var refreshRequest = new RefreshTokenRequest
        {
            RefreshToken = originalRefreshToken
        };
        var refreshResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token/refresh", refreshRequest);

        // Assert
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);
        var refreshResult = await refreshResponse.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(refreshResult);
        Assert.NotEqual(originalAccessToken, refreshResult.AccessToken);
        Assert.NotEqual(originalRefreshToken, refreshResult.RefreshToken);
    }

    [Fact]
    public async Task RefreshToken_InvalidRefreshToken_ReturnsUnauthorized()
    {
        await CleanDatabaseAsync();

        // Arrange
        var request = new RefreshTokenRequest
        {
            RefreshToken = "invalid-refresh-token-12345"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token/refresh", request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RefreshToken_ReuseRefreshToken_ShouldFail()
    {
        await CleanDatabaseAsync();

        // Arrange - Issue and refresh once
        var principalId = await CreateTestPrincipal("reuse-test-principal");
        var issueRequest = new IssueTokenRequest
        {
            PrincipalId = principalId.ToString()
        };
        var issueResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token", issueRequest);
        var issueResult = await issueResponse.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(issueResult);

        var refreshRequest = new RefreshTokenRequest
        {
            RefreshToken = issueResult.RefreshToken
        };
        await Client.PostAsJsonAsync("/iam/v1/auth/token/refresh", refreshRequest);

        // Act - Try to reuse the same refresh token
        var reuseResponse = await Client.PostAsJsonAsync("/iam/v1/auth/token/refresh", refreshRequest);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, reuseResponse.StatusCode);
    }

    [Fact]
    public async Task GetJwks_ReturnsValidJwksFormat()
    {
        await CleanDatabaseAsync();

        // Act
        var response = await Client.GetAsync("/iam/v1/auth/.well-known/jwks.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var jwks = await response.Content.ReadAsStringAsync();
        Assert.NotNull(jwks);
        Assert.Contains("\"keys\"", jwks);
        Assert.Contains("\"kty\"", jwks);
        Assert.Contains("\"RSA\"", jwks);
        Assert.Contains("\"use\"", jwks);
        Assert.Contains("\"sig\"", jwks);
        Assert.Contains("\"n\"", jwks);
        Assert.Contains("\"e\"", jwks);
    }

    [Fact]
    public async Task GetJwks_MultipleRequests_ReturnsSameKey()
    {
        await CleanDatabaseAsync();

        // Act
        var response1 = await Client.GetAsync("/iam/v1/auth/.well-known/jwks.json");
        var response2 = await Client.GetAsync("/iam/v1/auth/.well-known/jwks.json");

        // Assert
        var jwks1 = await response1.Content.ReadAsStringAsync();
        var jwks2 = await response2.Content.ReadAsStringAsync();
        Assert.Equal(jwks1, jwks2); // Key should be consistent
    }

    [Fact]
    public async Task IssueToken_WithRoleBindings_IncludesRoleClaims()
    {
        await CleanDatabaseAsync();

        // Arrange - Create principal with role binding
        var principalId = await CreateTestPrincipal("role-claims-test");

        // Create permission and role
        var serviceName = "role-claims-service";
        var permRequest = new RegisterPermissionsRequest
        {
            ServiceName = serviceName,
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = $"{serviceName}.data.read", Description = "Read" }
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
                }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/roles/register", roleRequest);

        // Bind role to principal
        var grantRequest = new GrantRoleRequest
        {
            RoleId = $"roles.{serviceName}.reader"
        };
        await Client.PostAsJsonAsync($"/iam/v1/principals/{principalId}/roles", grantRequest);

        // Act - Issue token
        var tokenRequest = new IssueTokenRequest
        {
            PrincipalId = principalId.ToString()
        };
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token", tokenRequest);
        var result = await response.Content.ReadFromJsonAsync<TokenResponse>();

        // Assert - Check for role and permission claims
        Assert.NotNull(result);
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(result.AccessToken);

        Assert.Contains(jwtToken.Claims, c => c.Type == "role" && c.Value == $"roles.{serviceName}.reader");
        Assert.Contains(jwtToken.Claims, c => c.Type == "permission" && c.Value == $"{serviceName}.data.read");
    }

    [Fact]
    public async Task IssueToken_ExpiredBinding_DoesNotIncludeExpiredRole()
    {
        await CleanDatabaseAsync();

        // Arrange
        var principalId = await CreateTestPrincipal("expired-binding-test");

        // Create permission and role
        var serviceName = "expired-binding-service";
        var permRequest = new RegisterPermissionsRequest
        {
            ServiceName = serviceName,
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = $"{serviceName}.data.read", Description = "Read" }
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
                    RoleId = $"{serviceName}/temp-role",
                    Description = "Temporary",
                    PermissionIds = new List<string> { $"{serviceName}.data.read" },
                    IsCustom = false
                }
            }
        };
        await Client.PostAsJsonAsync("/iam/v1/roles/register", roleRequest);

        // Bind role with past expiration
        var grantRequest = new GrantRoleRequest
        {
            RoleId = $"{serviceName}/temp-role",
            ExpiresAt = DateTime.UtcNow.AddMinutes(-1) // Expired
        };
        await Client.PostAsJsonAsync($"/iam/v1/principals/{principalId}/roles", grantRequest);

        // Act - Issue token
        var tokenRequest = new IssueTokenRequest
        {
            PrincipalId = principalId.ToString()
        };
        var response = await Client.PostAsJsonAsync("/iam/v1/auth/token", tokenRequest);
        var result = await response.Content.ReadFromJsonAsync<TokenResponse>();

        // Assert - Should not include expired role
        Assert.NotNull(result);
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(result.AccessToken);

        Assert.DoesNotContain(jwtToken.Claims, c => c.Type == "role" && c.Value == $"{serviceName}/temp-role");
    }
}
