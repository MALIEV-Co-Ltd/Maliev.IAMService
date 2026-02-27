using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace Maliev.IAMService.Application.Services;

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

    /// <summary>
    /// Gets the unique identifier for the current key (Key ID / kid).
    /// </summary>
    string GetKeyId();
}

/// <summary>
/// Singleton service that manages the RSA key pair for JWT signing.
/// Ensures consistent keys across all requests and service instances.
/// </summary>
public class RsaKeyProvider : IRsaKeyProvider
{
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _signingKey;
    private readonly string _keyId;
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
        _keyId = DeriveKeyId(_rsa);
        _signingKey = new RsaSecurityKey(_rsa) { KeyId = _keyId };
    }

    /// <inheritdoc />
    public RSA GetRsa() => _rsa;

    /// <inheritdoc />
    public RsaSecurityKey GetSigningKey() => _signingKey;

    /// <inheritdoc />
    public string GetKeyId() => _keyId;

    private string DeriveKeyId(RSA rsa)
    {
        var parameters = rsa.ExportParameters(false);
        var hash = SHA256.HashData(parameters.Modulus!);
        return Convert.ToHexString(hash).Substring(0, 16).ToLower();
    }

    private RSA LoadOrCreateRsaKey(IConfiguration configuration)
    {
        var keyBase64 = configuration["Jwt:PrivateKey"];
        var isProduction = configuration["ASPNETCORE_ENVIRONMENT"] == "Production";

        if (!string.IsNullOrEmpty(keyBase64))
        {
            try
            {
                var decodedString = Encoding.UTF8.GetString(Convert.FromBase64String(keyBase64));
                var rsa = RSA.Create();

                if (decodedString.Contains("BEGIN PRIVATE KEY"))
                {
                    rsa.ImportFromPem(decodedString);
                }
                else
                {
                    rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(keyBase64), out _);
                }

                _logger.LogInformation("Loaded existing RSA private key for JWT signing");
                return rsa;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load RSA private key from configuration");
                if (isProduction)
                {
                    throw new InvalidOperationException("Failed to load mandatory Jwt:PrivateKey in Production environment.", ex);
                }
            }
        }

        if (isProduction)
        {
            throw new InvalidOperationException("Jwt:PrivateKey must be configured in Production environment to ensure consistent token signing across instances.");
        }

        var newRsa = RSA.Create(2048);
        _logger.LogWarning("Generated new RSA key for JWT signing. This key should be persisted in configuration for consistency.");

        return newRsa;
    }
}
