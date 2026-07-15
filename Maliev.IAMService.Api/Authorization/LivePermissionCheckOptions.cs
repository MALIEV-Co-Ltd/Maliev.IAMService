namespace Maliev.IAMService.Api.Authorization;

/// <summary>
/// Configures callers and resource limits for authoritative permission checks.
/// </summary>
public sealed class LivePermissionCheckOptions
{
    /// <summary>Gets or sets the service names allowed to bypass the permission cache.</summary>
    public string[] AllowedServices { get; set; } = [];

    /// <summary>Gets or sets Base64-encoded SHA-256 credential hashes keyed by allowlisted service name.</summary>
    public Dictionary<string, string> CredentialHashes { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Gets or sets the maximum live checks per service within the configured window.</summary>
    public int ServicePermitLimit { get; set; } = 3000;

    /// <summary>Gets or sets the maximum live checks per target principal within the configured window.</summary>
    public int TargetPermitLimit { get; set; } = 120;

    /// <summary>Gets or sets the sliding-window duration in seconds.</summary>
    public int WindowSeconds { get; set; } = 60;

    /// <summary>Gets or sets the number of segments in the sliding window.</summary>
    public int SegmentsPerWindow { get; set; } = 4;

    /// <summary>Gets or sets the maximum concurrent live checks handled by one IAM pod.</summary>
    public int ConcurrencyLimit { get; set; } = 8;

    /// <summary>Gets or sets the maximum number of target-principal limiter partitions retained per pod.</summary>
    public int TargetLimiterCapacity { get; set; } = 4096;

    /// <summary>Gets or sets how many idle minutes a target-principal limiter remains eligible for reuse.</summary>
    public int TargetLimiterIdleMinutes { get; set; } = 10;

    /// <summary>
    /// Determines whether every distinct allowlisted service has a well-formed SHA-256 credential verifier.
    /// </summary>
    /// <returns><see langword="true"/> when the allowlist and verifier map form a complete configuration.</returns>
    public bool HasCompleteCredentialCoverage()
    {
        if (AllowedServices is not { Length: > 0 }
            || CredentialHashes is null
            || AllowedServices.Any(string.IsNullOrWhiteSpace)
            || AllowedServices.Distinct(StringComparer.OrdinalIgnoreCase).Count() != AllowedServices.Length)
        {
            return false;
        }

        foreach (var serviceName in AllowedServices)
        {
            if (!CredentialHashes.TryGetValue(serviceName, out var configuredHash)
                || string.IsNullOrWhiteSpace(configuredHash))
            {
                return false;
            }

            try
            {
                if (Convert.FromBase64String(configuredHash).Length != System.Security.Cryptography.SHA256.HashSizeInBytes)
                {
                    return false;
                }
            }
            catch (FormatException)
            {
                return false;
            }
        }

        return true;
    }
}
