using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Maliev.IAMService.Tests.Testing;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Maliev.IAMService.Api.Authorization;
using Moq;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>Verifies the isolated Auth-to-IAM token-issuance capability boundary.</summary>
public sealed class TokenIssuanceCapabilityTests : BaseIntegrationTest
{
    private const string Route = "/iam/v1/auth/token-issuance/resolve-permissions";

    public TokenIssuanceCapabilityTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task ResolvePermissions_ExactTargetBoundCapability_ReturnsOk()
    {
        var configuredOptions = Factory.Services
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(TokenIssuanceCapabilityAuthentication.Scheme);
        Assert.Equal("https://auth.test.maliev.com", configuredOptions.TokenValidationParameters.ValidIssuer);
        Assert.Equal("https://iam.test.maliev.com/auth/token-issuance", configuredOptions.TokenValidationParameters.ValidAudience);
        Assert.Single(configuredOptions.TokenValidationParameters.IssuerSigningKeyResolver!(
            string.Empty,
            null,
            "auth-capability-test-key",
            configuredOptions.TokenValidationParameters));

        var principalId = Guid.NewGuid();
        using var client = CreateCapabilityClient(Factory.CreateTokenIssuanceCapability(principalId));

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ResolvePermissions_NotBeforePrecedesIssuedAtAndThirtySecondLifetime_ReturnsOk()
    {
        var principalId = Guid.NewGuid();
        using var client = CreateCapabilityClient(Factory.CreateTokenIssuanceCapability(principalId));

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public void CapabilityAuthentication_ProductionTrustUsesCanonicalIssuerAndAudience()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{TokenIssuanceCapabilityAuthentication.ConfigurationSection}:Issuer"] =
                    "https://attacker.example",
                [$"{TokenIssuanceCapabilityAuthentication.ConfigurationSection}:Audience"] =
                    "https://attacker.example/iam"
            })
            .Build();
        var services = new ServiceCollection();
        services.AddTokenIssuanceCapabilityAuthentication(
            configuration,
            Mock.Of<IHostEnvironment>(candidate => candidate.EnvironmentName == Environments.Production));
        using var provider = services.BuildServiceProvider();

        var validationParameters = provider
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(TokenIssuanceCapabilityAuthentication.Scheme)
            .TokenValidationParameters;

        Assert.Equal("https://auth.maliev.com", validationParameters.ValidIssuer);
        Assert.Equal("https://iam.maliev.com/auth/token-issuance", validationParameters.ValidAudience);
    }

    [Fact]
    public async Task CapabilityAuthentication_MissingMaximumLifetime_DefaultsToThirtySeconds()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTokenIssuanceCapabilityAuthentication(
            new ConfigurationBuilder().Build(),
            Mock.Of<IHostEnvironment>(candidate => candidate.EnvironmentName == Environments.Production));
        using var provider = services.BuildServiceProvider();
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var issuedAtSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var thirtySecondResult = await authorization.AuthorizeAsync(
            CreateCapabilityPrincipal(issuedAtSeconds, issuedAtSeconds - 1, issuedAtSeconds + 30),
            resource: null,
            TokenIssuanceCapabilityAuthentication.Policy);
        var thirtyOneSecondResult = await authorization.AuthorizeAsync(
            CreateCapabilityPrincipal(issuedAtSeconds, issuedAtSeconds - 1, issuedAtSeconds + 31),
            resource: null,
            TokenIssuanceCapabilityAuthentication.Policy);

        Assert.True(thirtySecondResult.Succeeded);
        Assert.False(thirtyOneSecondResult.Succeeded);
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("61")]
    public async Task CapabilityAuthentication_InvalidMaximumLifetime_FailsClosed(string configuredMaximumLifetime)
    {
        using var signingKey = RSA.Create(2048);
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{TokenIssuanceCapabilityAuthentication.ConfigurationSection}:MaximumLifetimeSeconds"] =
                    configuredMaximumLifetime,
                [$"{TokenIssuanceCapabilityAuthentication.ConfigurationSection}:PublicKeys:test-key"] =
                    Convert.ToBase64String(signingKey.ExportSubjectPublicKeyInfo())
            })
            .Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTokenIssuanceCapabilityAuthentication(
            configuration,
            Mock.Of<IHostEnvironment>(candidate => candidate.EnvironmentName == Environments.Production));
        using var provider = services.BuildServiceProvider();
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var issuedAtSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var result = await authorization.AuthorizeAsync(
            CreateCapabilityPrincipal(issuedAtSeconds, issuedAtSeconds - 1, issuedAtSeconds + 1),
            resource: null,
            TokenIssuanceCapabilityAuthentication.Policy);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task ResolvePermissions_TargetDoesNotMatchBody_ReturnsForbidden()
    {
        using var client = CreateCapabilityClient(Factory.CreateTokenIssuanceCapability(Guid.NewGuid()));

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = Guid.NewGuid().ToString("D") });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("resource")]
    [InlineData("time")]
    [InlineData("ip")]
    public async Task ResolvePermissions_UnboundResolutionContext_ReturnsForbidden(string contextField)
    {
        var principalId = Guid.NewGuid();
        using var client = CreateCapabilityClient(Factory.CreateTokenIssuanceCapability(principalId));
        var request = new Dictionary<string, object>
        {
            ["PrincipalId"] = principalId.ToString("D"),
            [contextField switch
            {
                "resource" => "ResourcePath",
                "time" => "RequestTime",
                _ => "RequestIp"
            }] = contextField switch
            {
                "resource" => "organizations/other",
                "time" => DateTime.UtcNow,
                _ => "203.0.113.10"
            }
        };

        using var response = await client.PostAsJsonAsync(Route, request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ResolvePermissions_LegacyPlatformTokenCannotUseCapabilityRoute()
    {
        using var client = Factory.CreateAuthenticatedClientWithAllPermissions();

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = Guid.NewGuid().ToString("D") });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ResolvePermissions_LegacyRouteRemainsAvailable()
    {
        using var client = Factory.CreateAuthenticatedClientWithAllPermissions();

        using var response = await client.PostAsJsonAsync(
            "/iam/v1/auth/resolve-permissions",
            new { PrincipalId = Guid.NewGuid().ToString("D") });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("sub", "urn:maliev:service:not-auth")]
    [InlineData("service_name", "OtherService")]
    [InlineData("client_id", "other-service")]
    [InlineData("user_type", "employee")]
    [InlineData("purpose", "iam-registration")]
    [InlineData("permissions", "*")]
    [InlineData("permissions", "iam.auth.check-permission")]
    [InlineData("target_principal_id", "not-a-guid")]
    public async Task ResolvePermissions_IncorrectRequiredClaim_ReturnsForbidden(string claimType, string value)
    {
        var principalId = Guid.NewGuid();
        var token = Factory.CreateTokenIssuanceCapability(principalId, claims => ReplaceClaim(claims, claimType, value));
        using var client = CreateCapabilityClient(token);

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("jti")]
    [InlineData("iat")]
    [InlineData("service_name")]
    [InlineData("client_id")]
    [InlineData("user_type")]
    [InlineData("purpose")]
    [InlineData("target_principal_id")]
    [InlineData("permissions")]
    public async Task ResolvePermissions_MissingRequiredClaim_ReturnsForbidden(string claimType)
    {
        var principalId = Guid.NewGuid();
        var token = Factory.CreateTokenIssuanceCapability(
            principalId,
            claims => claims.RemoveAll(claim => claim.Type == claimType));
        using var client = CreateCapabilityClient(token);

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("sub", "urn:maliev:service:auth")]
    [InlineData("jti", "11111111-1111-1111-1111-111111111111")]
    [InlineData("iat", "1")]
    [InlineData("service_name", "AuthService")]
    [InlineData("client_id", "auth-service")]
    [InlineData("user_type", "service")]
    [InlineData("purpose", "iam.permission-resolution")]
    [InlineData("target_principal_id", "11111111-1111-1111-1111-111111111111")]
    [InlineData("permissions", "iam.auth.resolve-permissions")]
    public async Task ResolvePermissions_DuplicateRequiredClaim_ReturnsForbidden(string claimType, string value)
    {
        var principalId = Guid.NewGuid();
        var token = Factory.CreateTokenIssuanceCapability(
            principalId,
            claims => claims.Add(new Claim(claimType, value)));
        using var client = CreateCapabilityClient(token);

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        var expectedStatus = claimType is "sub" or "jti" or "iat"
            ? HttpStatusCode.Unauthorized
            : HttpStatusCode.Forbidden;
        Assert.Equal(expectedStatus, response.StatusCode);
    }

    [Theory]
    [InlineData("role", "service-account")]
    [InlineData("roles", "roles.platform.owner")]
    [InlineData("permission", "iam.auth.resolve-permissions")]
    [InlineData("permissions", "iam.auth.check-permission")]
    public async Task ResolvePermissions_AdditionalAuthorityClaim_ReturnsForbidden(string claimType, string value)
    {
        var principalId = Guid.NewGuid();
        var token = Factory.CreateTokenIssuanceCapability(
            principalId,
            claims => claims.Add(new Claim(claimType, value)));
        using var client = CreateCapabilityClient(token);

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ResolvePermissions_WrongIssuer_ReturnsUnauthorized()
    {
        var principalId = Guid.NewGuid();
        using var client = CreateCapabilityClient(Factory.CreateTokenIssuanceCapability(
            principalId,
            issuer: "https://attacker.test.maliev.com"));

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ResolvePermissions_WrongAudience_ReturnsUnauthorized()
    {
        var principalId = Guid.NewGuid();
        using var client = CreateCapabilityClient(Factory.CreateTokenIssuanceCapability(
            principalId,
            audience: "https://other.test.maliev.com"));

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ResolvePermissions_MultipleAudiences_ReturnsForbidden()
    {
        var principalId = Guid.NewGuid();
        using var client = CreateCapabilityClient(Factory.CreateTokenIssuanceCapability(
            principalId,
            audiences:
            [
                "https://iam.test.maliev.com/auth/token-issuance",
                "https://other.test.maliev.com"
            ]));

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ResolvePermissions_UnknownOrMissingKeyId_ReturnsUnauthorized()
    {
        var principalId = Guid.NewGuid();
        foreach (var keyId in new string?[] { "unknown-key", null })
        {
            using var client = CreateCapabilityClient(Factory.CreateTokenIssuanceCapability(principalId, keyId: keyId));
            using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    [Fact]
    public async Task ResolvePermissions_WrongSignature_ReturnsUnauthorized()
    {
        using var wrongKey = RSA.Create(2048);
        var credentials = new SigningCredentials(
            new RsaSecurityKey(wrongKey) { KeyId = "auth-capability-test-key" },
            SecurityAlgorithms.RsaSha256);
        var principalId = Guid.NewGuid();
        using var client = CreateCapabilityClient(Factory.CreateTokenIssuanceCapability(
            principalId,
            signingCredentials: credentials));

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ResolvePermissions_SymmetricAlgorithm_ReturnsUnauthorized()
    {
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes("not-a-shared-key-but-long-enough-for-test-only"))
            {
                KeyId = "auth-capability-test-key"
            },
            SecurityAlgorithms.HmacSha256);
        var principalId = Guid.NewGuid();
        using var client = CreateCapabilityClient(Factory.CreateTokenIssuanceCapability(
            principalId,
            signingCredentials: credentials));

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ResolvePermissions_ExpiredFutureOrOverlongLifetime_ReturnsUnauthorized()
    {
        var principalId = Guid.NewGuid();
        var now = DateTime.UtcNow;
        var windows = new[]
        {
            (now.AddMinutes(-2), now.AddMinutes(-1), HttpStatusCode.Unauthorized),
            (now.AddMinutes(1), now.AddMinutes(2), HttpStatusCode.Unauthorized),
            (now.AddSeconds(-1), now.AddSeconds(61), HttpStatusCode.Forbidden)
        };

        foreach (var (notBefore, expires, expectedStatusCode) in windows)
        {
            using var client = CreateCapabilityClient(Factory.CreateTokenIssuanceCapability(
                principalId,
                notBefore: notBefore,
                expires: expires));
            using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });
            Assert.Equal(expectedStatusCode, response.StatusCode);
        }
    }

    [Theory]
    [InlineData(-59, -59, 30, (int)HttpStatusCode.Forbidden)]
    [InlineData(-10, -1, 30, (int)HttpStatusCode.Forbidden)]
    public async Task ResolvePermissions_OffsetIssuedAtWindow_IsRejected(
        int issuedAtOffsetSeconds,
        int notBeforeOffsetSeconds,
        int expiresOffsetSeconds,
        int expectedStatusCode)
    {
        var principalId = Guid.NewGuid();
        var now = DateTime.UtcNow;
        var token = Factory.CreateTokenIssuanceCapability(
            principalId,
            claims => ReplaceClaim(
                claims,
                JwtRegisteredClaimNames.Iat,
                new DateTimeOffset(now.AddSeconds(issuedAtOffsetSeconds)).ToUnixTimeSeconds().ToString()),
            notBefore: now.AddSeconds(notBeforeOffsetSeconds),
            expires: now.AddSeconds(expiresOffsetSeconds));
        using var client = CreateCapabilityClient(token);

        using var response = await client.PostAsJsonAsync(Route, new { PrincipalId = principalId.ToString("D") });

        Assert.Equal((HttpStatusCode)expectedStatusCode, response.StatusCode);
    }

    private HttpClient CreateCapabilityClient(string token)
    {
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static void ReplaceClaim(List<Claim> claims, string claimType, string value)
    {
        claims.RemoveAll(claim => claim.Type == claimType);
        claims.Add(new Claim(claimType, value));
    }

    private static ClaimsPrincipal CreateCapabilityPrincipal(long issuedAt, long notBefore, long expires)
    {
        var identity = new ClaimsIdentity(
        [
            new Claim(JwtRegisteredClaimNames.Sub, "urn:maliev:service:auth"),
            new Claim(JwtRegisteredClaimNames.Aud, "https://iam.maliev.com/auth/token-issuance"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("D")),
            new Claim(JwtRegisteredClaimNames.Iat, issuedAt.ToString()),
            new Claim(JwtRegisteredClaimNames.Nbf, notBefore.ToString()),
            new Claim(JwtRegisteredClaimNames.Exp, expires.ToString()),
            new Claim("service_name", "AuthService"),
            new Claim("client_id", "auth-service"),
            new Claim("user_type", "service"),
            new Claim("purpose", "iam.permission-resolution"),
            new Claim("target_principal_id", Guid.NewGuid().ToString("D")),
            new Claim("permissions", "iam.auth.resolve-permissions")
        ], TokenIssuanceCapabilityAuthentication.Scheme);
        return new ClaimsPrincipal(identity);
    }
}
