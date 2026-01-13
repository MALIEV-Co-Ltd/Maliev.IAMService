using System.Security.Cryptography;
using System.Text;
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

        if (!string.IsNullOrEmpty(keyBase64))
        {
            try
            {
                // Decode Base64-encoded PEM
                var privateKeyBytes = Convert.FromBase64String(keyBase64);
                var privateKeyString = Encoding.UTF8.GetString(privateKeyBytes);

                // Extract the base64 content between PEM headers
                var lines = privateKeyString.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                var base64Content = string.Join("", lines.Where(l => !l.StartsWith("-----")));

                // Decode the PKCS#8 key bytes
                var keyBytes = Convert.FromBase64String(base64Content);

                // Import RSA private key using PKCS#8 format
                var rsa = RSA.Create();
                rsa.ImportPkcs8PrivateKey(keyBytes, out _);

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

        return newRsa;
    }
}
