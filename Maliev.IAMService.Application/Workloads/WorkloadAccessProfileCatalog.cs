using Maliev.IAMService.Application.Validators;

namespace Maliev.IAMService.Application.Workloads;

/// <summary>
/// Describes one additional resource-scoped role grant in a workload profile.
/// </summary>
/// <param name="RoleId">Canonical server-owned role identifier.</param>
/// <param name="ResourcePath">Exact hierarchical resource root for the grant.</param>
/// <param name="Permissions">Exact permissions assigned within the resource root.</param>
public sealed record WorkloadAccessGrant(
    string RoleId,
    string ResourcePath,
    IReadOnlyList<string> Permissions);

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
    IReadOnlyList<string> Permissions)
{
    /// <summary>Gets the optional canonical principal identifier owned by this profile.</summary>
    public Guid? PrincipalId { get; init; }

    /// <summary>Gets the additional resource-scoped grants owned by this profile.</summary>
    public IReadOnlyList<WorkloadAccessGrant> AdditionalGrants { get; init; } = [];
}

/// <summary>
/// Validated catalog of server-owned workload access profiles.
/// </summary>
public sealed class WorkloadAccessProfileCatalog
{
    private const int MaximumRoleIdLength = 255;
    private const int MaximumResourcePathLength = 500;
    private const int MaximumWorkloadIdLength = 100;
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
            ["country.countries.read"])
        {
            AdditionalGrants =
            [
                new WorkloadAccessGrant(
                    "roles.workloads.contact-service.v1.upload-contacts",
                    "folders/contacts",
                    ["upload.files.upload", "upload.files.download", "upload.files.delete"])
            ]
        },
        new WorkloadAccessProfile(
            "search-service",
            1,
            "roles.workloads.search-service.v1",
            ["iam.auth.check-permission"]),
        new WorkloadAccessProfile(
            "registry-service",
            1,
            "roles.workloads.registry-service.v1",
            ["iam.auth.check-permission"]),
        new WorkloadAccessProfile(
            "country-service",
            1,
            "roles.workloads.country-service.v1",
            ["iam.auth.check-permission"]),
        new WorkloadAccessProfile(
            "currency-service",
            1,
            "roles.workloads.currency-service.v1",
            ["iam.auth.check-permission"]),
        new WorkloadAccessProfile(
            "accounting-service",
            1,
            "roles.workloads.accounting-service.v1",
            ["iam.auth.check-permission"]),
        new WorkloadAccessProfile(
            "pricing-service",
            1,
            "roles.workloads.pricing-service.v1",
            [
                "iam.auth.check-permission",
                "material.materials.read",
                "job.jobs.read",
                "currency.rates.read"
            ])
        {
            PrincipalId = new Guid("18181818-1818-1818-1818-181818181818")
        },
        new WorkloadAccessProfile(
            "material-service",
            1,
            "roles.workloads.material-service.v1",
            [
                "iam.auth.check-permission",
                "supplier.supplier-references.read"
            ])
        {
            PrincipalId = new Guid("19191919-1919-1919-1919-191919191919")
        }
    ]);

    /// <summary>Initializes and validates a catalog.</summary>
    /// <param name="profiles">Profiles to register.</param>
    public WorkloadAccessProfileCatalog(IEnumerable<WorkloadAccessProfile> profiles)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        var validated = new Dictionary<(string, int), WorkloadAccessProfile>();
        var canonicalPrincipalOwners = new Dictionary<Guid, string>();
        var workloadPrincipalPolicies = new Dictionary<string, Guid?>(StringComparer.Ordinal);
        foreach (var profile in profiles)
        {
            var additionalGrants = profile.AdditionalGrants
                .Select(grant => grant with
                {
                    Permissions = Array.AsReadOnly(grant.Permissions.ToArray())
                })
                .ToArray();
            var registeredProfile = profile with
            {
                Permissions = Array.AsReadOnly(profile.Permissions.ToArray()),
                AdditionalGrants = Array.AsReadOnly(additionalGrants)
            };
            Validate(registeredProfile);
            if (workloadPrincipalPolicies.TryGetValue(
                    registeredProfile.WorkloadId,
                    out var existingPrincipalPolicy) &&
                existingPrincipalPolicy != registeredProfile.PrincipalId)
            {
                throw new ArgumentException(
                    $"Workload '{registeredProfile.WorkloadId}' has inconsistent canonical principal policy across versions.",
                    nameof(profiles));
            }

            workloadPrincipalPolicies.TryAdd(
                registeredProfile.WorkloadId,
                registeredProfile.PrincipalId);
            if (registeredProfile.PrincipalId is { } principalId &&
                canonicalPrincipalOwners.TryGetValue(principalId, out var owningWorkloadId) &&
                !string.Equals(owningWorkloadId, registeredProfile.WorkloadId, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"Canonical workload principal '{principalId:D}' is assigned to more than one workload.",
                    nameof(profiles));
            }

            if (registeredProfile.PrincipalId is { } canonicalPrincipalId)
            {
                canonicalPrincipalOwners.TryAdd(canonicalPrincipalId, registeredProfile.WorkloadId);
            }

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
        if (!IsCanonicalHyphenatedSegment(profile.WorkloadId, MaximumWorkloadIdLength) ||
            profile.Version <= 0 ||
            profile.PrincipalId == Guid.Empty ||
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
        if (profile.RoleId.Length > MaximumRoleIdLength ||
            !string.Equals(profile.RoleId, expectedRoleId, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Workload profile role must be the canonical server-owned role '{expectedRoleId}'.", nameof(profile));
        }

        ValidatePermissions(profile.Permissions, nameof(profile));
        var roleIds = new HashSet<string>(StringComparer.Ordinal) { profile.RoleId };
        var scopedAuthority = new HashSet<(string ResourcePath, string Permission)>();
        foreach (var grant in profile.AdditionalGrants)
        {
            var expectedPrefix = $"{profile.RoleId}.";
            var suffix = grant.RoleId.StartsWith(expectedPrefix, StringComparison.Ordinal)
                ? grant.RoleId[expectedPrefix.Length..]
                : string.Empty;
            if (!IsCanonicalHyphenatedSegment(suffix, MaximumRoleIdLength) ||
                grant.RoleId.Length > MaximumRoleIdLength ||
                !roleIds.Add(grant.RoleId))
            {
                throw new ArgumentException("Additional workload roles must use a unique canonical suffix owned by the base role.", nameof(profile));
            }

            if (!IsCanonicalResourcePath(grant.ResourcePath))
            {
                throw new ArgumentException("Additional workload grants require a canonical non-global resource path.", nameof(profile));
            }

            ValidatePermissions(grant.Permissions, nameof(profile));
            foreach (var permission in grant.Permissions)
            {
                if (profile.Permissions.Contains(permission, StringComparer.Ordinal) ||
                    !scopedAuthority.Add((grant.ResourcePath, permission)))
                {
                    throw new ArgumentException("Additional workload grants cannot duplicate global or scoped authority.", nameof(profile));
                }
            }
        }
    }

    private static void ValidatePermissions(IReadOnlyList<string> permissions, string parameterName)
    {
        if (permissions.Count == 0 ||
            permissions.Any(permission => !PermissionFormatValidator.IsValid(permission) || permission.Contains('*', StringComparison.Ordinal)) ||
            permissions.Distinct(StringComparer.Ordinal).Count() != permissions.Count)
        {
            throw new ArgumentException("Workload grants require unique canonical non-wildcard permissions.", parameterName);
        }
    }

    private static bool IsCanonicalResourcePath(string resourcePath) =>
        !string.IsNullOrWhiteSpace(resourcePath) &&
        resourcePath.Length <= MaximumResourcePathLength &&
        !resourcePath.Contains('*', StringComparison.Ordinal) &&
        resourcePath.Split('/').All(segment => IsCanonicalHyphenatedSegment(segment, MaximumResourcePathLength));

    private static bool IsCanonicalHyphenatedSegment(string value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximumLength &&
        char.IsAsciiLetterOrDigit(value[0]) &&
        char.IsAsciiLetterOrDigit(value[^1]) &&
        !value.Contains("--", StringComparison.Ordinal) &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character == '-') &&
        string.Equals(value, value.ToLowerInvariant(), StringComparison.Ordinal);
}
