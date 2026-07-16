namespace Maliev.IAMService.Application.Workloads;

/// <summary>
/// Describes a versioned, server-owned workload access profile.
/// </summary>
/// <param name="WorkloadId">Canonical workload identifier.</param>
/// <param name="Version">Profile version.</param>
/// <param name="RoleId">Server-owned role identifier.</param>
/// <param name="Permissions">Exact permissions assigned by the profile.</param>
public sealed record WorkloadAccessProfile(
    string WorkloadId,
    int Version,
    string RoleId,
    IReadOnlyList<string> Permissions);

/// <summary>
/// Validated catalog of server-owned workload access profiles.
/// </summary>
public sealed class WorkloadAccessProfileCatalog
{
    private readonly IReadOnlyDictionary<(string WorkloadId, int Version), WorkloadAccessProfile> _profiles;

    /// <summary>Gets the production profile catalog.</summary>
    public static WorkloadAccessProfileCatalog Default { get; } = new(
    [
        new WorkloadAccessProfile(
            "auth-service",
            1,
            "roles.workloads.auth-service.v1",
            ["iam.auth.resolve-permissions"]),
        new WorkloadAccessProfile(
            "contact-service",
            1,
            "roles.workloads.contact-service.v1",
            [
                "country.countries.read",
                "upload.files.upload",
                "upload.files.download",
                "upload.files.delete"
            ])
    ]);

    /// <summary>Initializes and validates a catalog.</summary>
    /// <param name="profiles">Profiles to register.</param>
    public WorkloadAccessProfileCatalog(IEnumerable<WorkloadAccessProfile> profiles)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        var validated = new Dictionary<(string, int), WorkloadAccessProfile>();
        foreach (var profile in profiles)
        {
            var registeredProfile = profile with
            {
                Permissions = Array.AsReadOnly(profile.Permissions.ToArray())
            };
            Validate(registeredProfile);
            if (!validated.TryAdd((registeredProfile.WorkloadId, registeredProfile.Version), registeredProfile))
            {
                throw new ArgumentException($"Duplicate workload profile '{registeredProfile.WorkloadId}' version {registeredProfile.Version}.", nameof(profiles));
            }
        }

        _profiles = validated;
    }

    /// <summary>Gets a profile by canonical workload ID and version.</summary>
    /// <param name="workloadId">Canonical workload ID.</param>
    /// <param name="version">Profile version.</param>
    /// <returns>The matching profile.</returns>
    /// <exception cref="KeyNotFoundException">No profile is registered.</exception>
    public WorkloadAccessProfile Get(string workloadId, int version) =>
        _profiles.TryGetValue((workloadId, version), out var profile)
            ? profile
            : throw new KeyNotFoundException($"No workload access profile exists for '{workloadId}' version {version}.");

    private static void Validate(WorkloadAccessProfile profile)
    {
        if (string.IsNullOrWhiteSpace(profile.WorkloadId) ||
            profile.WorkloadId.Any(character => !(char.IsAsciiLetterOrDigit(character) || character == '-')) ||
            !string.Equals(profile.WorkloadId, profile.WorkloadId.ToLowerInvariant(), StringComparison.Ordinal) ||
            profile.Version <= 0 ||
            string.IsNullOrWhiteSpace(profile.RoleId) ||
            profile.Permissions.Count == 0)
        {
            throw new ArgumentException("Workload profiles must use a canonical lowercase ID, positive version, role, and permissions.", nameof(profile));
        }

        if (string.Equals(profile.RoleId, "roles.platform.owner", StringComparison.OrdinalIgnoreCase) ||
            profile.Permissions.Any(permission => permission == "*" || permission.Contains('*', StringComparison.Ordinal)))
        {
            throw new ArgumentException("Workload profiles cannot grant Platform Owner or wildcard authority.", nameof(profile));
        }

        var expectedRoleId = $"roles.workloads.{profile.WorkloadId}.v{profile.Version}";
        if (!string.Equals(profile.RoleId, expectedRoleId, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Workload profile role must be the canonical server-owned role '{expectedRoleId}'.", nameof(profile));
        }
    }
}
