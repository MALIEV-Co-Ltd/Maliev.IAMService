using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;

namespace Maliev.IAMService.Application.Services;

/// <summary>
/// Service for issuing and managing JWT tokens with RS256 signing.
/// Uses 2048-bit RSA key pairs for token signing and supports token refresh with cryptographically secure tokens.
/// Tokens include principal claims, role claims, and permission claims with configurable expiration (default 60 minutes).
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Issues a new JWT access token for a principal with RS256 signing.
    /// Resolves all permissions and roles for the principal and embeds them as claims.
    /// Also generates a refresh token stored in Redis with 7-day expiration.
    /// </summary>
    /// <param name="request">Token request containing principal ID, optional resource scope, and expiration time.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Token response with access token (JWT), refresh token, and expiration details.</returns>
    Task<TokenResponse> IssueTokenAsync(IssueTokenRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Refreshes an access token using a valid refresh token.
    /// Validates the refresh token, invalidates it, and issues a new token pair.
    /// </summary>
    /// <param name="request">Refresh request containing the refresh token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>New token response with fresh access and refresh tokens.</returns>
    Task<TokenResponse> RefreshTokenAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the JSON Web Key Set (JWKS) containing the public key for token verification.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>JSON string containing the JWKS with public key information.</returns>
    Task<string> GetJwksAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Implementation of JWT token service using RS256 signing with 2048-bit RSA keys.
/// Issues tokens with embedded permission and role claims, manages refresh tokens in Redis.
/// </summary>
public class TokenService : ITokenService
{
    private readonly IPermissionResolver _permissionResolver;
    private readonly IPrincipalService _principalService;
    private readonly ICacheService _cacheService;
    private readonly IAuditService _auditService;
    private readonly ILogger<TokenService> _logger;
    private readonly IConfiguration _configuration;
    private readonly IRsaKeyProvider _rsaKeyProvider;

    private readonly System.Security.Cryptography.RSA _rsa;
    private readonly RsaSecurityKey _signingKey;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly int _defaultExpirationMinutes;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenService"/> class.
    /// </summary>
    /// <param name="permissionResolver">The permission resolver.</param>
    /// <param name="principalService">The principal service.</param>
    /// <param name="cacheService">The cache service.</param>
    /// <param name="auditService">The audit service.</param>
    /// <param name="configuration">The configuration.</param>
    /// <param name="rsaKeyProvider">The RSA key provider.</param>
    /// <param name="logger">The logger.</param>
    public TokenService(
        IPermissionResolver permissionResolver,
        IPrincipalService principalService,
        ICacheService cacheService,
        IAuditService auditService,
        IConfiguration configuration,
        IRsaKeyProvider rsaKeyProvider,
        ILogger<TokenService> logger)
    {
        _permissionResolver = permissionResolver;
        _principalService = principalService;
        _cacheService = cacheService;
        _auditService = auditService;
        _configuration = configuration;
        _rsaKeyProvider = rsaKeyProvider;
        _logger = logger;

        _issuer = configuration["Jwt:Issuer"] ?? "Maliev.IAMService";
        _audience = configuration["Jwt:Audience"] ?? "Maliev.Services";
        _defaultExpirationMinutes = configuration.GetValue<int>("Jwt:DefaultExpirationMinutes", 60);

        _rsa = _rsaKeyProvider.GetRsa();
        _signingKey = _rsaKeyProvider.GetSigningKey();
    }

    /// <inheritdoc />
    public async Task<TokenResponse> IssueTokenAsync(IssueTokenRequest request, CancellationToken cancellationToken = default)
    {
        var principalGuid = await _principalService.ResolvePrincipalIdAsync(request.PrincipalId, cancellationToken);

        var principal = await _principalService.GetByIdAsync(principalGuid, cancellationToken);
        if (principal == null)
            throw new InvalidOperationException($"Principal {request.PrincipalId} not found");

        var resolveRequest = new ResolvePermissionsRequest
        {
            PrincipalId = principalGuid.ToString(),
            ResourcePath = request.ResourcePath
        };
        var permissionsResponse = await _permissionResolver.ResolvePermissionsAsync(resolveRequest, cancellationToken);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, principalGuid.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("principal_id", principalGuid.ToString()),
            new("principal_type", principal.PrincipalType)
        };

        if (!string.IsNullOrEmpty(principal.Email))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, principal.Email));
        }

        foreach (var permission in permissionsResponse.Permissions)
        {
            claims.Add(new Claim("permission", permission));
        }

        foreach (var roleId in permissionsResponse.Roles)
        {
            claims.Add(new Claim("role", roleId));
        }

        if (!string.IsNullOrEmpty(request.ResourcePath))
        {
            claims.Add(new Claim("resource_path", request.ResourcePath));
        }

        var expirationMinutes = request.ExpiresInMinutes ?? _defaultExpirationMinutes;
        var issuedAt = DateTime.UtcNow;
        var expiresAt = issuedAt.AddMinutes(expirationMinutes);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = _issuer,
            Audience = _audience,
            IssuedAt = issuedAt,
            Expires = expiresAt,
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var accessToken = tokenHandler.WriteToken(token);

        var refreshToken = GenerateRefreshToken();
        await StoreRefreshToken(principalGuid, refreshToken, expiresAt.AddDays(7), request.ResourcePath, cancellationToken);

        await _auditService.LogAsync("ISSUE_TOKEN", principalGuid, new Dictionary<string, object>
        {
            ["principal_id"] = principalGuid,
            ["expires_at"] = expiresAt,
            ["permissions_count"] = permissionsResponse.Permissions.Count,
            ["roles_count"] = permissionsResponse.Roles.Count
        }, cancellationToken);

        _logger.LogInformation("Issued JWT token for principal {PrincipalId} ({PrincipalGuid}), expires at {ExpiresAt}",
            request.PrincipalId, principalGuid, expiresAt);

        return new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = (int)TimeSpan.FromMinutes(expirationMinutes).TotalSeconds,
            RefreshToken = refreshToken,
            IssuedAt = issuedAt,
            ExpiresAt = expiresAt
        };
    }

    /// <inheritdoc />
    public async Task<TokenResponse> RefreshTokenAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default)
    {
        var storedToken = await GetStoredRefreshToken(request.RefreshToken, cancellationToken);
        if (storedToken == null)
        {
            _logger.LogWarning("Invalid refresh token attempt");
            throw new InvalidOperationException("Invalid refresh token");
        }

        if (storedToken.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Expired refresh token used for principal {PrincipalId}", storedToken.PrincipalId);
            throw new InvalidOperationException("Refresh token has expired");
        }

        await InvalidateRefreshToken(request.RefreshToken, cancellationToken);

        var issueRequest = new IssueTokenRequest
        {
            PrincipalId = storedToken.PrincipalId.ToString(),
            ResourcePath = storedToken.ResourcePath
        };

        return await IssueTokenAsync(issueRequest, cancellationToken);
    }

    /// <inheritdoc />
    public Task<string> GetJwksAsync(CancellationToken cancellationToken = default)
    {
        var parameters = _rsa.ExportParameters(false);

        var jwk = new
        {
            kty = "RSA",
            use = "sig",
            kid = _rsaKeyProvider.GetKeyId(),
            alg = "RS256",
            n = WebEncoders.Base64UrlEncode(parameters.Modulus!),
            e = WebEncoders.Base64UrlEncode(parameters.Exponent!)
        };

        var jwks = new
        {
            keys = new[] { jwk }
        };

        var json = JsonSerializer.Serialize(jwks, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        return Task.FromResult(json);
    }

    /// <summary>
    /// Generates a cryptographically secure refresh token using RandomNumberGenerator.
    /// Token is 32 bytes (256 bits) of random data encoded as base64 string.
    /// </summary>
    /// <returns>Base64-encoded random token string.</returns>
    private string GenerateRefreshToken()
    {
        var randomBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        return Convert.ToBase64String(randomBytes);
    }

    /// <summary>
    /// Stores a refresh token in Redis cache with 7-day expiration.
    /// </summary>
    /// <param name="principalId">The principal ID the token is issued to.</param>
    /// <param name="refreshToken">The refresh token string.</param>
    /// <param name="expiresAt">Token expiration timestamp.</param>
    /// <param name="resourcePath">Optional hierarchical resource path for resource-scoped tokens.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task StoreRefreshToken(Guid principalId, string refreshToken, DateTime expiresAt, string? resourcePath, CancellationToken cancellationToken)
    {
        var tokenData = new RefreshTokenData
        {
            PrincipalId = principalId,
            RefreshToken = refreshToken,
            ExpiresAt = expiresAt,
            ResourcePath = resourcePath
        };

        var cacheKey = $"iam:refresh_token:{refreshToken}";
        var expiration = expiresAt - DateTime.UtcNow;

        await _cacheService.SetAsync(cacheKey, tokenData, expiration, cancellationToken);
    }

    /// <summary>
    /// Retrieves stored refresh token data from Redis cache.
    /// </summary>
    /// <param name="refreshToken">The refresh token to look up.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Refresh token data if found; otherwise null.</returns>
    private async Task<RefreshTokenData?> GetStoredRefreshToken(string refreshToken, CancellationToken cancellationToken)
    {
        var cacheKey = $"iam:refresh_token:{refreshToken}";
        return await _cacheService.GetAsync<RefreshTokenData>(cacheKey, cancellationToken);
    }

    /// <summary>
    /// Invalidates a refresh token by removing it from Redis cache.
    /// </summary>
    /// <param name="refreshToken">The refresh token to invalidate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task InvalidateRefreshToken(string refreshToken, CancellationToken cancellationToken)
    {
        var cacheKey = $"iam:refresh_token:{refreshToken}";
        await _cacheService.RemoveAsync(cacheKey, cancellationToken);
    }

    private class RefreshTokenData
    {
        /// <summary>Gets or sets the principal ID.</summary>
        public Guid PrincipalId { get; set; }

        /// <summary>Gets or sets the refresh token string.</summary>
        public string RefreshToken { get; set; } = null!;

        /// <summary>Gets or sets the token expiration time.</summary>
        public DateTime ExpiresAt { get; set; }

        /// <summary>Gets or sets the optional resource path.</summary>
        public string? ResourcePath { get; set; }
    }
}
