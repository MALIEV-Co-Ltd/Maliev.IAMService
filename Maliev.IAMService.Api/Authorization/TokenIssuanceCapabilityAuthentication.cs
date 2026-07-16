using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace Maliev.IAMService.Api.Authorization;

/// <summary>Defines the isolated AuthService token-issuance capability boundary.</summary>
public static class TokenIssuanceCapabilityAuthentication
{
    /// <summary>The dedicated authentication scheme.</summary>
    public const string Scheme = "AuthTokenIssuanceCapability";

    /// <summary>The authorization policy requiring an exact AuthService capability.</summary>
    public const string Policy = "AuthTokenIssuanceCapabilityPolicy";

    /// <summary>The configuration section containing public trust material.</summary>
    public const string ConfigurationSection = "IAM:TokenIssuanceCapability";

    private const string ProductionIssuer = "https://auth.maliev.com";
    private const string ProductionAudience = "https://iam.maliev.com/auth/token-issuance";
    private const string ExpectedSubject = "urn:maliev:service:auth";
    private const string ExpectedServiceName = "AuthService";
    private const string ExpectedClientId = "auth-service";
    private const string ExpectedUserType = "service";
    private const string ExpectedPurpose = "iam.permission-resolution";
    private const string ExpectedPermission = "iam.auth.resolve-permissions";
    private const int DefaultMaximumLifetimeSeconds = 30;
    private const int MaximumMaximumLifetimeSeconds = 60;
    private static readonly string[] ForbiddenAuthorityClaimTypes =
    [
        "permission",
        "role",
        "roles",
        ClaimTypes.Role
    ];

    /// <summary>Adds the dedicated fail-closed authentication scheme and exact-claims policy.</summary>
    /// <param name="services">Application services.</param>
    /// <param name="configuration">Application configuration.</param>
    /// <param name="environment">Host environment used to isolate test-only trust identifiers.</param>
    /// <returns>The supplied service collection.</returns>
    public static IServiceCollection AddTokenIssuanceCapabilityAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        var section = configuration.GetSection(ConfigurationSection);
        var issuer = environment.IsEnvironment("Testing")
            ? ReadCanonicalHttpsIdentifier(section["Issuer"])
            : ProductionIssuer;
        var audience = environment.IsEnvironment("Testing")
            ? ReadCanonicalHttpsIdentifier(section["Audience"])
            : ProductionAudience;
        var maximumLifetimeSeconds = ReadMaximumLifetime(section["MaximumLifetimeSeconds"]);
        var signingKeys = LoadSigningKeys(section.GetSection("PublicKeys"));

        services.AddAuthentication()
            .AddJwtBearer(Scheme, options =>
            {
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    RequireSignedTokens = true,
                    RequireExpirationTime = true,
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidIssuer = issuer,
                    ValidateAudience = true,
                    ValidAudience = audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    LifetimeValidator = (notBefore, expires, _, _) =>
                    {
                        var now = DateTime.UtcNow;
                        return notBefore.HasValue &&
                            expires.HasValue &&
                            notBefore.Value <= now &&
                            expires.Value > now;
                    },
                    ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                    NameClaimType = JwtRegisteredClaimNames.Sub,
                    RoleClaimType = "roles",
                    IssuerSigningKeyResolver = (_, _, keyId, _) =>
                        keyId is not null && signingKeys.TryGetValue(keyId, out var key)
                            ? [key]
                            : []
                };
            });

        services.AddAuthorizationBuilder()
            .AddPolicy(Policy, policy =>
            {
                policy.AuthenticationSchemes.Add(Scheme);
                policy.RequireAuthenticatedUser();
                policy.RequireAssertion(context => HasExactClaims(
                    context.User,
                    DateTimeOffset.UtcNow,
                    maximumLifetimeSeconds,
                    audience));
            });

        return services;
    }

    /// <summary>Checks that the capability is bound to the requested principal.</summary>
    /// <param name="principal">Authenticated capability principal.</param>
    /// <param name="requestedPrincipalId">Principal from the permission-resolution request.</param>
    /// <returns><see langword="true"/> only for an exact canonical target match.</returns>
    public static bool IsBoundToTarget(ClaimsPrincipal principal, string requestedPrincipalId)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var targets = principal.FindAll("target_principal_id").Select(claim => claim.Value).ToArray();
        return targets.Length == 1 &&
            Guid.TryParseExact(requestedPrincipalId, "D", out var requested) &&
            Guid.TryParseExact(targets[0], "D", out var claimed) &&
            string.Equals(requestedPrincipalId, requested.ToString("D"), StringComparison.Ordinal) &&
            string.Equals(targets[0], claimed.ToString("D"), StringComparison.Ordinal) &&
            requested == claimed;
    }

    private static bool HasExactClaims(
        ClaimsPrincipal principal,
        DateTimeOffset now,
        int maximumLifetimeSeconds,
        string expectedAudience)
    {
        if (!HasSingleClaim(principal, JwtRegisteredClaimNames.Sub, ExpectedSubject) ||
            !HasSingleClaim(principal, JwtRegisteredClaimNames.Aud, expectedAudience) ||
            !HasSingleClaim(principal, "service_name", ExpectedServiceName) ||
            !HasSingleClaim(principal, "client_id", ExpectedClientId) ||
            !HasSingleClaim(principal, "user_type", ExpectedUserType) ||
            !HasSingleClaim(principal, "purpose", ExpectedPurpose) ||
            !HasSingleClaim(principal, "permissions", ExpectedPermission) ||
            ForbiddenAuthorityClaimTypes.Any(type => principal.FindAll(type).Any()))
        {
            return false;
        }

        var targets = principal.FindAll("target_principal_id").Select(claim => claim.Value).ToArray();
        var tokenIds = principal.FindAll(JwtRegisteredClaimNames.Jti).Select(claim => claim.Value).ToArray();
        var issuedAtValues = principal.FindAll(JwtRegisteredClaimNames.Iat).Select(claim => claim.Value).ToArray();
        var notBeforeValues = principal.FindAll(JwtRegisteredClaimNames.Nbf).Select(claim => claim.Value).ToArray();
        var expiresValues = principal.FindAll(JwtRegisteredClaimNames.Exp).Select(claim => claim.Value).ToArray();
        if (targets.Length != 1 ||
            !Guid.TryParseExact(targets[0], "D", out var target) ||
            !string.Equals(targets[0], target.ToString("D"), StringComparison.Ordinal) ||
            tokenIds.Length != 1 ||
            !Guid.TryParseExact(tokenIds[0], "D", out var tokenId) ||
            !string.Equals(tokenIds[0], tokenId.ToString("D"), StringComparison.Ordinal) ||
            issuedAtValues.Length != 1 ||
            !long.TryParse(issuedAtValues[0], NumberStyles.None, CultureInfo.InvariantCulture, out var issuedAtSeconds) ||
            notBeforeValues.Length != 1 ||
            !long.TryParse(notBeforeValues[0], NumberStyles.None, CultureInfo.InvariantCulture, out var notBeforeSeconds) ||
            expiresValues.Length != 1 ||
            !long.TryParse(expiresValues[0], NumberStyles.None, CultureInfo.InvariantCulture, out var expiresSeconds))
        {
            return false;
        }

        try
        {
            var issuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAtSeconds);
            var notBefore = DateTimeOffset.FromUnixTimeSeconds(notBeforeSeconds);
            var expires = DateTimeOffset.FromUnixTimeSeconds(expiresSeconds);
            return issuedAt <= now &&
                issuedAt >= now.AddSeconds(-maximumLifetimeSeconds) &&
                notBefore <= issuedAt &&
                issuedAt < expires &&
                expires - issuedAt <= TimeSpan.FromSeconds(maximumLifetimeSeconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static bool HasSingleClaim(ClaimsPrincipal principal, string claimType, string expectedValue)
    {
        var values = principal.FindAll(claimType).Select(claim => claim.Value).ToArray();
        return values.Length == 1 && string.Equals(values[0], expectedValue, StringComparison.Ordinal);
    }

    private static string ReadCanonicalHttpsIdentifier(string? configuredValue)
    {
        const string failClosedIdentifier = "https://invalid.invalid";
        if (string.IsNullOrWhiteSpace(configuredValue) ||
            !string.Equals(configuredValue, configuredValue.Trim(), StringComparison.Ordinal) ||
            !Uri.TryCreate(configuredValue, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            return failClosedIdentifier;
        }

        var canonical = uri.GetComponents(
            UriComponents.SchemeAndServer | UriComponents.Path,
            UriFormat.UriEscaped).TrimEnd('/');
        return string.Equals(configuredValue, canonical, StringComparison.Ordinal)
            ? canonical
            : failClosedIdentifier;
    }

    private static int ReadMaximumLifetime(string? configuredValue)
    {
        if (configuredValue is null)
        {
            return DefaultMaximumLifetimeSeconds;
        }

        return int.TryParse(configuredValue, NumberStyles.None, CultureInfo.InvariantCulture, out var value) &&
            value is > 0 and <= MaximumMaximumLifetimeSeconds
                ? value
                : 0;
    }

    private static IReadOnlyDictionary<string, SecurityKey> LoadSigningKeys(IConfigurationSection section)
    {
        var keys = new Dictionary<string, SecurityKey>(StringComparer.Ordinal);
        foreach (var child in section.GetChildren())
        {
            if (!IsCanonicalKeyId(child.Key) ||
                string.IsNullOrWhiteSpace(child.Value) ||
                !TryLoadPublicKey(child.Value, child.Key, out var key))
            {
                continue;
            }

            keys.TryAdd(child.Key, key);
        }

        return keys;
    }

    private static bool IsCanonicalKeyId(string keyId) =>
        keyId is { Length: >= 1 and <= 128 } &&
        string.Equals(keyId, keyId.Trim().ToLowerInvariant(), StringComparison.Ordinal) &&
        keyId.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    private static bool TryLoadPublicKey(string configuredValue, string keyId, out SecurityKey key)
    {
        key = null!;
        try
        {
            byte[] subjectPublicKeyInfo;
            if (configuredValue.Contains("BEGIN", StringComparison.Ordinal))
            {
                var pem = configuredValue.AsSpan();
                if (!PemEncoding.TryFind(pem, out var fields) ||
                    !pem[fields.Label].SequenceEqual("PUBLIC KEY"))
                {
                    return false;
                }

                var prefixEnd = fields.Location.Start.GetOffset(pem.Length);
                var suffixStart = fields.Location.End.GetOffset(pem.Length);
                if (!pem[..prefixEnd].Trim().IsEmpty || !pem[suffixStart..].Trim().IsEmpty)
                {
                    return false;
                }

                subjectPublicKeyInfo = Convert.FromBase64String(pem[fields.Base64Data].ToString());
            }
            else
            {
                subjectPublicKeyInfo = Convert.FromBase64String(configuredValue);
            }

            try
            {
                var rsa = RSA.Create();
                try
                {
                    rsa.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var bytesRead);
                    if (bytesRead != subjectPublicKeyInfo.Length || rsa.KeySize < 2048)
                    {
                        rsa.Dispose();
                        return false;
                    }

                    key = new RsaSecurityKey(rsa) { KeyId = keyId };
                    return true;
                }
                catch
                {
                    rsa.Dispose();
                    throw;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
            }
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException or ArgumentException)
        {
            return false;
        }
    }
}
