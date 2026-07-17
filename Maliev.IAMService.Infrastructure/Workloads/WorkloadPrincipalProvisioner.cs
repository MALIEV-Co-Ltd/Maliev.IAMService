using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Application.Services;
using Maliev.IAMService.Application.Workloads;
using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Maliev.IAMService.Infrastructure.Workloads;

/// <summary>
/// Atomically provisions canonical workload principals from server-owned profiles.
/// </summary>
public sealed class WorkloadPrincipalProvisioner : IWorkloadPrincipalProvisioner
{
    private const string ProvisionPermission = "iam.workload-principals.provision";
    private const string PlatformOwnerRole = "roles.platform.owner";
    private const string ManagedRoleDescription = "Server-owned least-privilege workload role.";
    private readonly IAMDbContext _dbContext;
    private readonly WorkloadAccessProfileCatalog _catalog;
    private readonly ICacheService _cacheService;

    /// <summary>Initializes the provisioner.</summary>
    /// <param name="dbContext">IAM database context.</param>
    /// <param name="catalog">Validated server-owned profile catalog.</param>
    /// <param name="cacheService">Permission cache service.</param>
    public WorkloadPrincipalProvisioner(
        IAMDbContext dbContext,
        WorkloadAccessProfileCatalog catalog,
        ICacheService cacheService)
    {
        _dbContext = dbContext;
        _catalog = catalog;
        _cacheService = cacheService;
    }

    /// <inheritdoc />
    public async Task<WorkloadPrincipalResponse> ProvisionAsync(
        string workloadId,
        ProvisionWorkloadPrincipalRequest request,
        Guid performedBy,
        CancellationToken cancellationToken = default)
    {
        if (request.OperationId == Guid.Empty || performedBy == Guid.Empty)
        {
            throw new ArgumentException("Operation and employee principal identifiers are required.");
        }

        WorkloadAccessProfile profile;
        try
        {
            profile = _catalog.Get(workloadId, request.ProfileVersion);
        }
        catch (KeyNotFoundException ex)
        {
            throw new WorkloadProvisioningConflictException(ex.Message);
        }

        ValidateRuntimeProfile(profile);
        var grants = GetExpectedGrants(profile);
        var requestHash = ComputeRequestHash(workloadId, request.ProfileVersion);

        var strategy = _dbContext.Database.CreateExecutionStrategy();
        var response = await strategy.ExecuteAsync(
            () => ProvisionTransactionAsync(workloadId, request, performedBy, profile, grants, requestHash, cancellationToken));
        await _cacheService.RemoveByPrefixAsync(IamPermissionCacheKeys.ForPermissions(response.PrincipalId), cancellationToken);
        return response;
    }

    private async Task<WorkloadPrincipalResponse> ProvisionTransactionAsync(
        string workloadId,
        ProvisionWorkloadPrincipalRequest request,
        Guid performedBy,
        WorkloadAccessProfile profile,
        IReadOnlyList<ExpectedWorkloadGrant> grants,
        string requestHash,
        CancellationToken cancellationToken)
    {
        _dbContext.ChangeTracker.Clear();
        await using var transaction = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        await _dbContext.Database.ExecuteSqlRawAsync(
            "LOCK TABLE principals IN SHARE ROW EXCLUSIVE MODE",
            cancellationToken);

        var actor = await _dbContext.Principals
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.PrincipalId == performedBy, cancellationToken);
        if (actor is null || !actor.IsActive || !string.Equals(actor.PrincipalType, "user", StringComparison.Ordinal))
        {
            throw new WorkloadProvisioningAuthorizationException("Provisioning requires an active employee IAM principal.");
        }

        var now = DateTime.UtcNow;
        var hasDirectAuthority = await _dbContext.PrincipalPermissionBindings
            .AsNoTracking()
            .AnyAsync(binding =>
                binding.PrincipalId == performedBy &&
                binding.PermissionId == ProvisionPermission &&
                (binding.ExpiresAt == null || binding.ExpiresAt > now) &&
                (binding.ResourcePath == null || binding.ResourcePath == string.Empty || binding.ResourcePath == "*"),
                cancellationToken);
        var hasRoleAuthority = await _dbContext.PrincipalRoleBindings
            .AsNoTracking()
            .AnyAsync(binding =>
                binding.PrincipalId == performedBy &&
                binding.RoleId.ToLower() != PlatformOwnerRole &&
                (binding.ExpiresAt == null || binding.ExpiresAt > now) &&
                (binding.ResourcePath == null || binding.ResourcePath == string.Empty || binding.ResourcePath == "*") &&
                binding.Role.RolePermissions.Any(permission => permission.PermissionId == ProvisionPermission),
                cancellationToken);
        if (!hasDirectAuthority && !hasRoleAuthority)
        {
            throw new WorkloadProvisioningAuthorizationException("Current persisted IAM authority is required to provision workload principals.");
        }

        var priorOperation = await _dbContext.WorkloadProvisioningOperations
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.OperationId == request.OperationId, cancellationToken);
        if (priorOperation is not null)
        {
            if (priorOperation.PerformedBy != performedBy ||
                !CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(priorOperation.RequestHash),
                    Convert.FromHexString(requestHash)))
            {
                throw new WorkloadProvisioningConflictException("The operation identifier was already used for a different request.");
            }

            await ValidateExactManagedStateAsync(
                priorOperation.PrincipalId,
                workloadId,
                profile,
                grants,
                cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return CreateResponse(profile, priorOperation.PrincipalId);
        }

        var principal = await _dbContext.Principals
            .SingleOrDefaultAsync(candidate => candidate.WorkloadId == workloadId, cancellationToken);
        if (principal is not null && principal.PrincipalType != "service_account")
        {
            throw new WorkloadProvisioningConflictException("The workload identifier belongs to an incompatible principal.");
        }

        if (principal is not null &&
            profile.PrincipalId is { } canonicalPrincipalId &&
            principal.PrincipalId != canonicalPrincipalId)
        {
            throw new WorkloadProvisioningConflictException(
                "The workload identifier belongs to a non-canonical principal.");
        }

        if (principal is null && profile.PrincipalId is { } expectedPrincipalId)
        {
            var principalIdOwner = await _dbContext.Principals
                .SingleOrDefaultAsync(candidate => candidate.PrincipalId == expectedPrincipalId, cancellationToken);
            if (principalIdOwner is not null)
            {
                throw new WorkloadProvisioningConflictException(
                    "The canonical workload principal identifier is already assigned.");
            }
        }

        principal ??= new Principal
        {
            PrincipalId = profile.PrincipalId ?? Guid.NewGuid(),
            PrincipalType = "service_account",
            WorkloadId = workloadId,
            DisplayName = $"{workloadId} workload",
            Email = $"{workloadId}@workload.maliev.local",
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        if (!principal.IsActive)
        {
            throw new WorkloadProvisioningConflictException("An inactive workload principal cannot be provisioned.");
        }

        if (_dbContext.Entry(principal).State == EntityState.Detached)
        {
            _dbContext.Principals.Add(principal);
        }

        var expectedPermissionIds = grants
            .SelectMany(grant => grant.Permissions)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var registeredPermissionIds = await _dbContext.Permissions
            .Where(permission => expectedPermissionIds.Contains(permission.PermissionId))
            .Select(permission => permission.PermissionId)
            .ToListAsync(cancellationToken);
        if (registeredPermissionIds.Count != expectedPermissionIds.Length)
        {
            throw new WorkloadProvisioningConflictException("The workload profile references permissions that are not registered.");
        }

        var expectedRoleIds = grants.Select(grant => grant.RoleId).ToArray();
        var roles = await _dbContext.Roles
            .Include(candidate => candidate.RolePermissions)
            .Where(candidate => expectedRoleIds.Contains(candidate.RoleId))
            .ToDictionaryAsync(candidate => candidate.RoleId, StringComparer.Ordinal, cancellationToken);
        foreach (var grant in grants)
        {
            if (!roles.TryGetValue(grant.RoleId, out var role))
            {
                role = new Role
                {
                    RoleId = grant.RoleId,
                    RoleName = GetExpectedRoleName(profile, grant.RoleId),
                    ServiceName = "iam",
                    Description = ManagedRoleDescription,
                    IsCustom = false,
                    CreatedBy = performedBy,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                    RolePermissions = grant.Permissions
                        .Select(permission => new RolePermission { RoleId = grant.RoleId, PermissionId = permission })
                        .ToList()
                };
                _dbContext.Roles.Add(role);
            }
            else if (!HasExpectedManagedRoleMetadata(role, profile, grant.RoleId) ||
                     !HasExactPermissions(role, grant.Permissions))
            {
                throw new WorkloadProvisioningConflictException("A server-owned workload role has drifted from its declared profile.");
            }
        }

        var directBindingExists = await _dbContext.PrincipalPermissionBindings
            .AnyAsync(candidate => candidate.PrincipalId == principal.PrincipalId, cancellationToken);
        if (directBindingExists)
        {
            throw new WorkloadProvisioningConflictException(
                "Managed workload principals cannot have direct permission bindings, including expired bindings.");
        }

        if (await _dbContext.ServiceAccountApiKeys
                .AnyAsync(candidate => candidate.PrincipalId == principal.PrincipalId, cancellationToken))
        {
            throw new WorkloadProvisioningConflictException("Managed workload principals cannot have IAM API keys.");
        }

        var bindings = await _dbContext.PrincipalRoleBindings
            .Where(candidate => candidate.PrincipalId == principal.PrincipalId)
            .ToListAsync(cancellationToken);
        var expectedBindingKeys = grants
            .Select(grant => (grant.RoleId, grant.ResourcePath))
            .ToHashSet();
        var existingBindingKeys = bindings
            .Select(binding => (binding.RoleId, binding.ResourcePath))
            .ToHashSet();
        if (bindings.Count > grants.Count ||
            existingBindingKeys.Count != bindings.Count ||
            bindings.Any(binding =>
                binding.ExpiresAt is not null ||
                !expectedBindingKeys.Contains((binding.RoleId, binding.ResourcePath))))
        {
            throw new WorkloadProvisioningConflictException("The workload principal has authority outside its exact declared profile.");
        }

        foreach (var grant in grants.Where(grant => !existingBindingKeys.Contains((grant.RoleId, grant.ResourcePath))))
        {
            _dbContext.PrincipalRoleBindings.Add(new PrincipalRoleBinding
            {
                BindingId = Guid.NewGuid(),
                PrincipalId = principal.PrincipalId,
                RoleId = grant.RoleId,
                ResourcePath = grant.ResourcePath,
                GrantedBy = performedBy,
                GrantedAt = DateTime.UtcNow
            });
        }

        _dbContext.WorkloadProvisioningOperations.Add(new WorkloadProvisioningOperation
        {
            OperationId = request.OperationId,
            WorkloadId = workloadId,
            ProfileVersion = request.ProfileVersion,
            RequestHash = requestHash,
            PrincipalId = principal.PrincipalId,
            PerformedBy = performedBy,
            CompletedAt = DateTime.UtcNow
        });
        _dbContext.IAMAuditLogs.Add(new IAMAuditLog
        {
            LogId = Guid.NewGuid(),
            Action = "PROVISION_WORKLOAD_PRINCIPAL",
            PrincipalId = principal.PrincipalId,
            RoleId = profile.RoleId,
            PerformedBy = performedBy,
            Timestamp = DateTime.UtcNow,
            Details = JsonSerializer.Serialize(new { workloadId, profileVersion = request.ProfileVersion, request.OperationId })
        });

        await _dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return CreateResponse(profile, principal.PrincipalId);
    }

    private static void ValidateRuntimeProfile(WorkloadAccessProfile profile)
    {
        var grants = GetExpectedGrants(profile);
        if (grants.Any(grant =>
                string.Equals(grant.RoleId, "roles.platform.owner", StringComparison.OrdinalIgnoreCase) ||
                grant.Permissions.Any(permission => permission.Contains('*', StringComparison.Ordinal)) ||
                (grant.ResourcePath is not null && grant.ResourcePath.Contains('*', StringComparison.Ordinal))))
        {
            throw new WorkloadProvisioningConflictException("Unsafe workload profiles cannot be provisioned.");
        }
    }

    private async Task ValidateExactManagedStateAsync(
        Guid principalId,
        string workloadId,
        WorkloadAccessProfile profile,
        IReadOnlyList<ExpectedWorkloadGrant> grants,
        CancellationToken cancellationToken)
    {
        var principal = await _dbContext.Principals
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.PrincipalId == principalId, cancellationToken);
        if (principal is null ||
            !principal.IsActive ||
            !string.Equals(principal.PrincipalType, "service_account", StringComparison.Ordinal) ||
            !string.Equals(principal.WorkloadId, workloadId, StringComparison.Ordinal) ||
            (profile.PrincipalId is { } canonicalPrincipalId && principal.PrincipalId != canonicalPrincipalId))
        {
            throw new WorkloadProvisioningConflictException("The recorded workload principal is missing, inactive, or has immutable identity drift.");
        }

        var expectedRoleIds = grants.Select(grant => grant.RoleId).ToArray();
        var roles = await _dbContext.Roles
            .AsNoTracking()
            .Include(candidate => candidate.RolePermissions)
            .Where(candidate => expectedRoleIds.Contains(candidate.RoleId))
            .ToListAsync(cancellationToken);
        if (roles.Count != grants.Count || grants.Any(grant =>
                roles.SingleOrDefault(role => role.RoleId == grant.RoleId) is not { } role ||
                !HasExpectedManagedRoleMetadata(role, profile, grant.RoleId) ||
                !HasExactPermissions(role, grant.Permissions)))
        {
            throw new WorkloadProvisioningConflictException("A server-owned workload role has drifted from its declared profile.");
        }

        var bindings = await _dbContext.PrincipalRoleBindings
            .AsNoTracking()
            .Where(binding => binding.PrincipalId == principalId)
            .ToListAsync(cancellationToken);
        var expectedBindingKeys = grants
            .Select(grant => (grant.RoleId, grant.ResourcePath))
            .ToHashSet();
        var actualBindingKeys = bindings
            .Select(binding => (binding.RoleId, binding.ResourcePath))
            .ToHashSet();
        if (bindings.Count != grants.Count ||
            actualBindingKeys.Count != bindings.Count ||
            !actualBindingKeys.SetEquals(expectedBindingKeys) ||
            bindings.Any(binding =>
                binding.ExpiresAt is not null ||
                !expectedBindingKeys.Contains((binding.RoleId, binding.ResourcePath))))
        {
            throw new WorkloadProvisioningConflictException("The workload principal binding has drifted from its exact declared profile.");
        }

        if (await _dbContext.PrincipalPermissionBindings
                .AsNoTracking()
                .AnyAsync(binding => binding.PrincipalId == principalId, cancellationToken))
        {
            throw new WorkloadProvisioningConflictException(
                "Managed workload principals cannot have direct permission bindings, including expired bindings.");
        }


        if (await _dbContext.ServiceAccountApiKeys
                .AsNoTracking()
                .AnyAsync(key => key.PrincipalId == principalId, cancellationToken))
        {
            throw new WorkloadProvisioningConflictException("Managed workload principals cannot have IAM API keys.");
        }
    }

    private static string ComputeRequestHash(string workloadId, int version) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{workloadId}\n{version}"))).ToLowerInvariant();

    private static bool HasExpectedManagedRoleMetadata(Role role, WorkloadAccessProfile profile, string roleId) =>
        string.Equals(role.RoleId, roleId, StringComparison.Ordinal) &&
        !role.IsCustom &&
        string.Equals(role.ServiceName, "iam", StringComparison.Ordinal) &&
        string.Equals(role.RoleName, GetExpectedRoleName(profile, roleId), StringComparison.Ordinal) &&
        string.Equals(role.Description, ManagedRoleDescription, StringComparison.Ordinal);

    private static bool HasExactPermissions(Role role, IReadOnlyList<string> permissions) =>
        role.RolePermissions
            .Select(permission => permission.PermissionId)
            .Order(StringComparer.Ordinal)
            .SequenceEqual(permissions.Order(StringComparer.Ordinal));

    private static string GetExpectedRoleName(WorkloadAccessProfile profile, string roleId)
    {
        var baseName = $"{profile.WorkloadId} workload v{profile.Version}";
        return string.Equals(roleId, profile.RoleId, StringComparison.Ordinal)
            ? baseName
            : $"{baseName} {roleId[(profile.RoleId.Length + 1)..]}";
    }

    private static IReadOnlyList<ExpectedWorkloadGrant> GetExpectedGrants(WorkloadAccessProfile profile) =>
    [
        new ExpectedWorkloadGrant(profile.RoleId, null, profile.Permissions),
        .. profile.AdditionalGrants.Select(grant =>
            new ExpectedWorkloadGrant(grant.RoleId, grant.ResourcePath, grant.Permissions))
    ];

    private static WorkloadPrincipalResponse CreateResponse(WorkloadAccessProfile profile, Guid principalId) => new()
    {
        WorkloadId = profile.WorkloadId,
        PrincipalId = principalId,
        ProfileVersion = profile.Version,
        RoleId = profile.RoleId,
        Bindings = GetExpectedGrants(profile)
            .Select(grant => new WorkloadPrincipalBindingResponse
            {
                RoleId = grant.RoleId,
                ResourcePath = grant.ResourcePath
            })
            .ToArray()
    };

    private sealed record ExpectedWorkloadGrant(
        string RoleId,
        string? ResourcePath,
        IReadOnlyList<string> Permissions);
}
