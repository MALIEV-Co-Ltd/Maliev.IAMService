using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using Maliev.IAMService.Data.Repositories;

namespace Maliev.IAMService.Api.Authorization;

/// <summary>
/// Options for service account authentication.
/// </summary>
public class ServiceAccountAuthOptions : AuthenticationSchemeOptions
{
}

// T131: Service account authentication handler for API key validation
/// <summary>
/// Authentication handler for validating service account API keys.
/// </summary>
public class ServiceAccountAuthHandler : AuthenticationHandler<ServiceAccountAuthOptions>
{
    private readonly IServiceAccountApiKeyRepository _apiKeyRepository;
    private readonly ILogger<ServiceAccountAuthHandler> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ServiceAccountAuthHandler"/> class.
    /// </summary>
    /// <param name="options">The options monitor.</param>
    /// <param name="loggerFactory">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    /// <param name="apiKeyRepository">The API key repository.</param>
    public ServiceAccountAuthHandler(
        IOptionsMonitor<ServiceAccountAuthOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder,
        IServiceAccountApiKeyRepository apiKeyRepository)
        : base(options, loggerFactory, encoder)
    {
        _apiKeyRepository = apiKeyRepository;
        _logger = loggerFactory.CreateLogger<ServiceAccountAuthHandler>();
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Check for Authorization header
        if (!Request.Headers.ContainsKey("Authorization"))
        {
            return AuthenticateResult.NoResult();
        }

        string? authHeader = Request.Headers["Authorization"].ToString();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        // Extract API key from Bearer token
        string apiKey = authHeader.Substring("Bearer ".Length).Trim();
        if (string.IsNullOrEmpty(apiKey) || apiKey.Length < 8)
        {
            _logger.LogWarning("Invalid API key format");
            return AuthenticateResult.Fail("Invalid API key format");
        }

        try
        {
            // Get prefix (first 8 characters)
            string keyPrefix = apiKey.Substring(0, 8);

            // Look up API key by prefix
            var storedKey = await _apiKeyRepository.GetByPrefixAsync(keyPrefix, Context.RequestAborted);
            if (storedKey == null)
            {
                _logger.LogWarning("API key not found for prefix {KeyPrefix}", keyPrefix);
                return AuthenticateResult.Fail("Invalid API key");
            }

            // Check if key is active
            if (!storedKey.IsActive)
            {
                _logger.LogWarning("Inactive API key used for principal {PrincipalId}", storedKey.PrincipalId);
                return AuthenticateResult.Fail("API key is not active");
            }

            // Check expiration
            if (storedKey.ExpiresAt.HasValue && storedKey.ExpiresAt.Value < DateTime.UtcNow)
            {
                _logger.LogWarning("Expired API key used for principal {PrincipalId}", storedKey.PrincipalId);
                return AuthenticateResult.Fail("API key has expired");
            }

            // Verify the API key hash
            if (!VerifyApiKey(apiKey, storedKey.KeyHash))
            {
                _logger.LogWarning("API key hash mismatch for principal {PrincipalId}", storedKey.PrincipalId);
                return AuthenticateResult.Fail("Invalid API key");
            }

            // Update last used timestamp (fire and forget)
            _ = Task.Run(async () =>
            {
                try
                {
                    storedKey.LastUsedAt = DateTime.UtcNow;
                    await _apiKeyRepository.UpdateAsync(storedKey, CancellationToken.None);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to update LastUsedAt for key {KeyId}", storedKey.KeyId);
                }
            });

            // Create claims for the service account
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, storedKey.PrincipalId.ToString()),
                new Claim(ClaimTypes.Name, storedKey.Principal?.Email ?? $"ServiceAccount-{storedKey.PrincipalId}"),
                new Claim("principal_type", "service_account"),
                new Claim("key_id", storedKey.KeyId.ToString())
            };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            _logger.LogInformation("Service account authenticated: {PrincipalId}", storedKey.PrincipalId);

            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error authenticating service account");
            return AuthenticateResult.Fail("Authentication error");
        }
    }

    // Verify API key against stored hash
    private bool VerifyApiKey(string apiKey, string storedHash)
    {
        try
        {
            // storedHash format: "salt:hash"
            var parts = storedHash.Split(':');
            if (parts.Length != 2)
            {
                _logger.LogWarning("Invalid stored hash format");
                return false;
            }

            byte[] salt = Convert.FromBase64String(parts[0]);
            string expectedHash = parts[1];

            // Hash the provided API key with the same salt
            string actualHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: apiKey,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));

            return actualHash == expectedHash;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying API key");
            return false;
        }
    }
}
