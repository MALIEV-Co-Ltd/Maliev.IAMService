using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;

namespace Maliev.IAMService.Api.Services;

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
    /// Refresh tokens are single-use and stored in Redis with 7-day TTL.
    /// </summary>
    /// <param name="request">Refresh request containing the refresh token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>New token response with fresh access and refresh tokens.</returns>
    Task<TokenResponse> RefreshTokenAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the JSON Web Key Set (JWKS) containing the public key for token verification.
    /// Exports only the public portion of the 2048-bit RSA key in JWK format.
    /// Used by downstream services to verify token signatures.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>JSON string containing the JWKS with public key information.</returns>
    Task<string> GetJwksAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Implementation of JWT token service using RS256 signing with 2048-bit RSA keys.
/// Issues tokens with embedded permission and role claims, manages refresh tokens in Redis.
/// Default token expiration is 60 minutes, refresh tokens expire after 7 days.
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

    // T141: RSA key pair for signing (2048-bit) - provided by singleton IRsaKeyProvider
    private readonly RSA _rsa;
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

        // T141: Get RSA key pair from singleton provider (ensures consistency across requests)
        _rsa = _rsaKeyProvider.GetRsa();
        _signingKey = _rsaKeyProvider.GetSigningKey();
    }

    /// <inheritdoc />
    public async Task<TokenResponse> IssueTokenAsync(IssueTokenRequest request, CancellationToken cancellationToken = default)
    {
        // T150: Resolve principal identifier to GUID
        var principalGuid = await _principalService.ResolvePrincipalIdAsync(request.PrincipalId, cancellationToken);

        // Validate principal exists
        var principal = await _principalService.GetByIdAsync(principalGuid, cancellationToken);
        if (principal == null)
            throw new InvalidOperationException($"Principal {request.PrincipalId} not found");

        // T142: Resolve permissions for the principal
        var resolveRequest = new ResolvePermissionsRequest
        {
            PrincipalId = principalGuid.ToString(),
            ResourcePath = request.ResourcePath
        };
        var permissionsResponse = await _permissionResolver.ResolvePermissionsAsync(resolveRequest, cancellationToken);

        // T142: Build JWT claims
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, principalGuid.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new Claim("principal_id", principalGuid.ToString()),
            new Claim("principal_type", principal.PrincipalType)
        };

        // Add email if present
        if (!string.IsNullOrEmpty(principal.Email))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, principal.Email));
        }

        // Add permissions as claims
        foreach (var permission in permissionsResponse.Permissions)
        {
            claims.Add(new Claim("permission", permission));
        }

        // Add roles as claims (T205: Use roles from resolver response)
        foreach (var roleId in permissionsResponse.Roles)
        {
            claims.Add(new Claim("role", roleId));
        }

        // Add resource scope if specified
        if (!string.IsNullOrEmpty(request.ResourcePath))
        {
            claims.Add(new Claim("resource_path", request.ResourcePath));
        }

        // T143: Token expiration (default 60 minutes)
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

        // T144: Generate refresh token
        var refreshToken = GenerateRefreshToken();
        await StoreRefreshToken(principalGuid, refreshToken, expiresAt.AddDays(7), request.ResourcePath, cancellationToken);

        // T147: Audit logging
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
        // Validate and retrieve stored refresh token
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

        // Invalidate the old refresh token
        await InvalidateRefreshToken(request.RefreshToken, cancellationToken);

        // Issue a new token
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
        var parameters = _rsa.ExportParameters(false); // Export public key only

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
    /// Loads an existing RSA private key from configuration or generates a new 2048-bit key.
    /// Key is loaded from "Jwt:PrivateKey" configuration as base64-encoded private key.
    /// If key doesn't exist, a new RSA-2048 key pair is generated and logged for storage.
    /// </summary>
    /// <returns>RSA instance with loaded or generated key pair.</returns>

    /// <summary>
    /// Generates a cryptographically secure refresh token using RNGCryptoServiceProvider.
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
    /// Token data includes principal ID, expiration time, and optional resource scope.
    /// Cache key format: "iam:refresh_token:{refreshToken}".
    /// </summary>
    /// <param name="principalId">The principal ID the token is issued to.</param>
    /// <param name="refreshToken">The refresh token string.</param>
    /// <param name="expiresAt">Token expiration timestamp (typically 7 days from issuance).</param>
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
    /// Returns null if token doesn't exist or has been invalidated.
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
    /// Called after successful token refresh to ensure single-use semantics.
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
        public Guid PrincipalId { get; set; }
        public string RefreshToken { get; set; } = null!;
        public DateTime ExpiresAt { get; set; }
        public string? ResourcePath { get; set; }
    }
}
