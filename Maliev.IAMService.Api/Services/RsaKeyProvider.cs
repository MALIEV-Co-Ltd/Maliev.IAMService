using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Maliev.IAMService.Api.Services;

/// <summary>
/// Interface for providing RSA key pair for JWT signing and verification.
/// </summary>
public interface IRsaKeyProvider
{
    /// <summary>
    /// Gets the RSA instance with the private key for signing.
    /// </summary>
    RSA GetRsa();

    /// <summary>
    /// Gets the RSA security key for signing.
    /// </summary>
    RsaSecurityKey GetSigningKey();
}

/// <summary>
/// Singleton service that manages the RSA key pair for JWT signing.
/// Ensures consistent keys across all requests and service instances.
/// </summary>
public class RsaKeyProvider : IRsaKeyProvider
{
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _signingKey;
    private readonly ILogger<RsaKeyProvider> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="RsaKeyProvider"/> class.
    /// </summary>
    /// <param name="configuration">The configuration.</param>
    /// <param name="logger">The logger.</param>
    public RsaKeyProvider(IConfiguration configuration, ILogger<RsaKeyProvider> logger)
    {
        _logger = logger;
        _rsa = LoadOrCreateRsaKey(configuration);
        _signingKey = new RsaSecurityKey(_rsa);
    }

    /// <inheritdoc />
    public RSA GetRsa() => _rsa;

    /// <inheritdoc />
    public RsaSecurityKey GetSigningKey() => _signingKey;

    private RSA LoadOrCreateRsaKey(IConfiguration configuration)
    {
        var keyBase64 = configuration["Jwt:PrivateKey"];

        if (!string.IsNullOrEmpty(keyBase64))
        {
            try
            {
                var rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(Convert.FromBase64String(keyBase64), out _);
                _logger.LogInformation("Loaded existing RSA private key for JWT signing");
                return rsa;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load RSA private key from configuration, generating new key");
            }
        }

        // Generate new 2048-bit RSA key
        var newRsa = RSA.Create(2048);
        _logger.LogWarning("Generated new RSA key for JWT signing. This key should be persisted in configuration.");

        // Log the private key (for development only - should be stored securely in production)
        var privateKey = newRsa.ExportRSAPrivateKey();
        var privateKeyBase64 = Convert.ToBase64String(privateKey);
        _logger.LogInformation("RSA Private Key (Base64): {PrivateKey}", privateKeyBase64);

        return newRsa;
    }
}
