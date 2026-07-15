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
        var requestHash = ComputeRequestHash(workloadId, request.ProfileVersion);

        var strategy = _dbContext.Database.CreateExecutionStrategy();
        var response = await strategy.ExecuteAsync(
            () => ProvisionTransactionAsync(workloadId, request, performedBy, profile, requestHash, cancellationToken));
        await _cacheService.RemoveByPrefixAsync($"iam:principal:{response.PrincipalId}:permissions", cancellationToken);
        return response;
    }

    private async Task<WorkloadPrincipalResponse> ProvisionTransactionAsync(
        string workloadId,
        ProvisionWorkloadPrincipalRequest request,
        Guid performedBy,
        WorkloadAccessProfile profile,
        string requestHash,
        CancellationToken cancellationToken)
    {
        await using var transaction = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        var priorOperation = await _dbContext.WorkloadProvisioningOperations
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.OperationId == request.OperationId, cancellationToken);
        if (priorOperation is not null)
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(priorOperation.RequestHash),
                    Convert.FromHexString(requestHash)))
            {
                throw new WorkloadProvisioningConflictException("The operation identifier was already used for a different request.");
            }

            await transaction.CommitAsync(cancellationToken);
            return CreateResponse(profile, priorOperation.PrincipalId);
        }

        var principal = await _dbContext.Principals
            .SingleOrDefaultAsync(candidate => candidate.WorkloadId == workloadId, cancellationToken);
        if (principal is not null && principal.PrincipalType != "service_account")
        {
            throw new WorkloadProvisioningConflictException("The workload identifier belongs to an incompatible principal.");
        }

        principal ??= new Principal
        {
            PrincipalId = Guid.NewGuid(),
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

        var missingPermissions = await _dbContext.Permissions
            .Where(permission => profile.Permissions.Contains(permission.PermissionId))
            .Select(permission => permission.PermissionId)
            .ToListAsync(cancellationToken);
        if (missingPermissions.Count != profile.Permissions.Count)
        {
            throw new WorkloadProvisioningConflictException("The workload profile references permissions that are not registered.");
        }

        var role = await _dbContext.Roles
            .Include(candidate => candidate.RolePermissions)
            .SingleOrDefaultAsync(candidate => candidate.RoleId == profile.RoleId, cancellationToken);
        if (role is null)
        {
            role = new Role
            {
                RoleId = profile.RoleId,
                RoleName = $"{workloadId} workload v{profile.Version}",
                ServiceName = "iam",
                Description = "Server-owned least-privilege workload role.",
                IsCustom = false,
                CreatedBy = performedBy,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                RolePermissions = profile.Permissions
                    .Select(permission => new RolePermission { RoleId = profile.RoleId, PermissionId = permission })
                    .ToList()
            };
            _dbContext.Roles.Add(role);
        }
        else if (!role.RolePermissions.Select(item => item.PermissionId).Order().SequenceEqual(profile.Permissions.Order()))
        {
            throw new WorkloadProvisioningConflictException("The server-owned workload role has drifted from its declared profile.");
        }

        var bindings = await _dbContext.PrincipalRoleBindings
            .Where(candidate => candidate.PrincipalId == principal.PrincipalId)
            .ToListAsync(cancellationToken);
        if (bindings.Any(binding => binding.RoleId == "roles.platform.owner" || binding.ResourcePath is not null))
        {
            throw new WorkloadProvisioningConflictException("The workload principal has an unsafe or scoped role binding.");
        }

        if (bindings.Any(binding => binding.RoleId != profile.RoleId))
        {
            throw new WorkloadProvisioningConflictException("The workload principal has authority outside its declared profile.");
        }

        if (bindings.Count == 0)
        {
            _dbContext.PrincipalRoleBindings.Add(new PrincipalRoleBinding
            {
                BindingId = Guid.NewGuid(),
                PrincipalId = principal.PrincipalId,
                RoleId = profile.RoleId,
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
        if (profile.RoleId == "roles.platform.owner" || profile.Permissions.Any(permission => permission.Contains('*', StringComparison.Ordinal)))
        {
            throw new WorkloadProvisioningConflictException("Unsafe workload profiles cannot be provisioned.");
        }
    }

    private static string ComputeRequestHash(string workloadId, int version) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{workloadId}\n{version}"))).ToLowerInvariant();

    private static WorkloadPrincipalResponse CreateResponse(WorkloadAccessProfile profile, Guid principalId) => new()
    {
        WorkloadId = profile.WorkloadId,
        PrincipalId = principalId,
        ProfileVersion = profile.Version,
        RoleId = profile.RoleId
    };
}
