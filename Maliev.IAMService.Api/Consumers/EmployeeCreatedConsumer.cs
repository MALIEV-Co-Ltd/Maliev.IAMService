using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Application.Services;
using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Infrastructure.Persistence;
using Maliev.MessagingContracts.Contracts.Employee;
using MassTransit;
using Microsoft.EntityFrameworkCore;

namespace Maliev.IAMService.Api.Consumers;

/// <summary>
/// Consumer for EmployeeCreated events.
/// Automatically provisions a Principal in the IAM system for new employees.
/// Grants <c>roles.platform.owner</c> (wildcard <c>*</c> permission) to the first
/// <c>@maliev.com</c> user if no human Platform Owner exists yet (bootstrap).
/// </summary>
/// <remarks>
/// First-login bootstrap flow (Google SSO):
/// <list type="number">
///   <item>AuthService: employee doesn't exist → calls EmployeeService, publishes EmployeeCreated event, starts polling ResolvePermissions every 500 ms for up to 10 s.</item>
///   <item>This consumer (async, RabbitMQ): creates Principal, detects no human Platform Owner → calls BootstrapAdminRoleAsync → creates role.platform.owner with wildcard permission, binds it, clears permission cache.</item>
///   <item>AuthService poll: once the binding is committed and cache is cleared, the next ResolvePermissions call returns roles → AuthService issues a JWT with permissions and stops polling.</item>
///   <item>IntranetBff OnTicketReceived: calls POST /bootstrap/promote (200 if consumer hasn't finished, 400 if it has), then always re-exchanges the token so the cookie JWT reflects the current DB state.</item>
/// </list>
///
/// Key invariants that must be preserved:
/// <list type="bullet">
///   <item><c>platformOwnerExists</c> queries MUST filter <c>PrincipalType == "user"</c> — system service principals also hold roles.platform.owner and must not count.</item>
///   <item><c>PermissionResolver</c> must NOT cache empty permission results — see its SetAsync guard.</item>
///   <item>IntranetBff must re-exchange token on both 200 and 400 from /bootstrap/promote.</item>
/// </list>
/// </remarks>
public class EmployeeCreatedConsumer : IConsumer<EmployeeCreatedEvent>
{
    private readonly IPrincipalRepository _principalRepository;
    private readonly IRoleRepository _roleRepository;
    private readonly IBindingRepository _bindingRepository;
    private readonly IPermissionRepository _permissionRepository;
    private readonly IAMDbContext _dbContext;
    private readonly ILogger<EmployeeCreatedConsumer> _logger;
    private readonly ICacheService _cacheService;
    private const string PlatformOwnerRoleId = "roles.platform.owner";

    /// <summary>
    /// Initializes a new instance of the <see cref="EmployeeCreatedConsumer"/> class.
    /// </summary>
    public EmployeeCreatedConsumer(
        IPrincipalRepository principalRepository,
        IRoleRepository roleRepository,
        IBindingRepository bindingRepository,
        IPermissionRepository permissionRepository,
        IAMDbContext dbContext,
        ILogger<EmployeeCreatedConsumer> logger,
        ICacheService cacheService)
    {
        _principalRepository = principalRepository;
        _roleRepository = roleRepository;
        _bindingRepository = bindingRepository;
        _permissionRepository = permissionRepository;
        _dbContext = dbContext;
        _logger = logger;
        _cacheService = cacheService;
    }

    /// <summary>
    /// Consumes the EmployeeCreatedEvent and provisions a Principal.
    /// </summary>
    public async Task Consume(ConsumeContext<EmployeeCreatedEvent> context)
    {
        var payload = context.Message.Payload;
        _logger.LogInformation("Processing EmployeeCreated event for {Email} (PrincipalId: {PrincipalId})",
            payload.Email, payload.PrincipalId);

        try
        {
            var existing = await _principalRepository.GetByIdAsync(payload.PrincipalId, context.CancellationToken);
            if (existing == null)
            {
                // Try finding by email to support pre-seeded bootstrap admins
                var allPrincipals = await _principalRepository.GetAllAsync(context.CancellationToken);
                existing = allPrincipals.FirstOrDefault(p => p.Email == payload.Email);

                if (existing != null)
                {
                    _logger.LogInformation("Principal for {Email} already exists with different ID {ExistingId}. Linking to employee {EmployeeId}",
                        payload.Email, existing.PrincipalId, payload.EmployeeId);

                    existing.LinkedService = "EmployeeService";
                    existing.LinkedEntityId = payload.EmployeeId;
                    await _principalRepository.UpdateAsync(existing, context.CancellationToken);

                    // We must use the EXISTING principal ID for bootstrapping to ensure roles match
                    await BootstrapAdminRoleAsync(existing.PrincipalId, context.CancellationToken);
                    return;
                }
            }

            if (existing != null)
            {
                _logger.LogInformation("Principal {PrincipalId} already exists, checking bootstrap status.", payload.PrincipalId);

                // Even if the principal exists, check if bootstrap is needed (handles retries/stale state).
                // ⚠ Keep PrincipalType == "user" — see comment near the bottom of Consume() for why
                //   filtering on type is required to exclude system service principals.
                var ownerExistsForExisting = await (
                    from b in _dbContext.PrincipalRoleBindings
                    join p in _dbContext.Principals on b.PrincipalId equals p.PrincipalId
                    where b.RoleId == PlatformOwnerRoleId && p.PrincipalType == "user"
                    select b.BindingId
                ).AnyAsync(context.CancellationToken);

                if (!ownerExistsForExisting && payload.Email.EndsWith("@maliev.com", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogInformation("No Platform Owner exists. Bootstrapping existing principal {Email} ({PrincipalId}).",
                        payload.Email, existing.PrincipalId);
                    await BootstrapAdminRoleAsync(existing.PrincipalId, context.CancellationToken);
                }
                return;
            }

            // Create the principal
            var principal = new Principal
            {
                PrincipalId = payload.PrincipalId,
                PrincipalType = "user",
                Email = payload.Email,
                DisplayName = payload.FullName,
                IsActive = true,
                LinkedService = "EmployeeService",
                LinkedEntityId = payload.EmployeeId,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            try
            {
                await _principalRepository.CreateAsync(principal, context.CancellationToken);
                _logger.LogInformation("Created Principal for {Email}", payload.Email);
            }
            catch (Microsoft.EntityFrameworkCore.DbUpdateException ex) when (ex.InnerException is Npgsql.PostgresException { SqlState: "23505" or "23503" })
            {
                _logger.LogInformation("Principal {PrincipalId} / {Email} already created by another process.", payload.PrincipalId, payload.Email);
            }

            // Grant Platform Owner to the first @maliev.com employee that logs in, if no owner exists yet.
            // Checking binding existence (not principal count) so retries and stale principals don't block bootstrap.
            //
            // ⚠ SYSTEM PRINCIPAL FILTER — the join on PrincipalType == "user" is NOT optional.
            //
            // PrincipalService auto-registers every .NET service/worker as a "system" principal and
            // immediately grants it roles.platform.owner so services can call each other at startup.
            // Without the PrincipalType filter, the query would find those system bindings and conclude
            // that a human Platform Owner already exists, silently skipping bootstrap entirely.
            // The first real user would then have zero permissions and receive 403 everywhere.
            var platformOwnerExists = await (
                from b in _dbContext.PrincipalRoleBindings
                join p in _dbContext.Principals on b.PrincipalId equals p.PrincipalId
                where b.RoleId == PlatformOwnerRoleId && p.PrincipalType == "user"
                select b.BindingId
            ).AnyAsync(context.CancellationToken);

            if (!platformOwnerExists && payload.Email.EndsWith("@maliev.com", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogInformation("No Platform Owner exists. Bootstrapping {Email} ({PrincipalId}).", payload.Email, payload.PrincipalId);
                await BootstrapAdminRoleAsync(payload.PrincipalId, context.CancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to provision principal for employee {EmployeeId}", payload.EmployeeId);
            throw;
        }
    }

    private async Task BootstrapAdminRoleAsync(Guid principalId, CancellationToken ct)
    {
        // Create Platform Owner role with ALL permissions for first user bootstrapping
        // This role automatically receives new permissions as services register them
        await CreateAndAssignRoleAsync(
            principalId,
            PlatformOwnerRoleId,
            "Platform Owner",
            "platform",
            "Full ownership and administrative access to all platform services and resources",
            isCustom: false,
            serviceFilter: null,  // ALL permissions across all services
            ct);
    }

    /// <summary>
    /// Creates and assigns a role with specified permissions to the principal.
    /// Retries if permissions don't exist yet (handles timing issues).
    /// </summary>
    private async Task CreateAndAssignRoleAsync(
        Guid principalId,
        string roleId,
        string roleName,
        string serviceName,
        string description,
        bool isCustom,
        string? serviceFilter,  // null = all permissions, otherwise filter by service
        CancellationToken ct)
    {
        const int maxRetries = 6;  // 1s, 2s, 4s, 8s, 16s, 32s = ~63 seconds total
        int attempt = 0;
        bool success = false;

        while (attempt < maxRetries && !success)
        {
            try
            {
                var role = await _roleRepository.GetByIdAsync(roleId, ct);

                // If not in DB, check if it's already being tracked from a previous failed attempt in this scope
                role ??= _roleRepository.GetTracked(roleId);

                if (role == null)
                {
                    _logger.LogInformation(
                        "Attempt {Attempt}/{MaxRetries}: Creating role {RoleId}",
                        attempt + 1, maxRetries, roleId);

                    // Fetch permissions (with optional service filter)
                    var allPermissions = await _permissionRepository.GetAllAsync(ct);
                    var filteredPermissions = string.IsNullOrEmpty(serviceFilter)
                        ? allPermissions
                        : allPermissions.Where(p => p.ServiceName == serviceFilter).ToList();

                    // Platform Owner only needs the wildcard '*' permission (added below),
                    // so don't block on waiting for service permissions to be registered.
                    if (!filteredPermissions.Any() && roleId != PlatformOwnerRoleId)
                    {
                        if (attempt < maxRetries - 1)
                        {
                            var delay = (int)Math.Pow(2, attempt) * 1000;  // Exponential backoff
                            _logger.LogWarning(
                                "No permissions found yet for service '{ServiceFilter}'. " +
                                "Retrying in {Delay}ms (attempt {Attempt}/{MaxRetries})",
                                serviceFilter ?? "ALL", delay, attempt + 1, maxRetries);
                            await Task.Delay(delay, ct);
                            attempt++;
                            continue;
                        }
                        else
                        {
                            _logger.LogWarning(
                                "No permissions found for service '{ServiceFilter}' after {MaxRetries} attempts. " +
                                "Creating role without permissions.",
                                serviceFilter ?? "ALL", maxRetries);
                            filteredPermissions = new List<Permission>();
                        }
                    }

                    role = new Role
                    {
                        RoleId = roleId,
                        RoleName = roleName,
                        ServiceName = serviceName,
                        Description = description,
                        IsCustom = isCustom,
                        CreatedBy = IAMDbContext.SystemPrincipalId,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow,
                        RolePermissions = filteredPermissions.Select(p => new RolePermission
                        {
                            RoleId = roleId,
                            PermissionId = p.PermissionId
                        }).ToList()
                    };

                    // Add wildcard permission for Platform Owner
                    if (roleId == PlatformOwnerRoleId)
                    {
                        // T220: Ensure wildcard permission exists in database before linking
                        var wildcardPerm = await _permissionRepository.GetByIdAsync("*", ct);
                        if (wildcardPerm == null)
                        {
                            _logger.LogInformation("Creating missing wildcard permission during bootstrapping");
                            wildcardPerm = new Permission
                            {
                                PermissionId = "*",
                                ServiceName = "platform",
                                ResourceType = "all",
                                Action = "all",
                                Description = "Wildcard permission for full access",
                                RegisteredAt = DateTime.UtcNow
                            };
                            try
                            {
                                await _permissionRepository.CreateAsync(wildcardPerm, ct);
                            }
                            catch (Microsoft.EntityFrameworkCore.DbUpdateException ex) when (ex.InnerException is Npgsql.PostgresException { SqlState: "23505" })
                            {
                                // Ignore if already created by another process
                            }
                        }

                        if (!role.RolePermissions.Any(rp => rp.PermissionId == "*"))
                        {
                            role.RolePermissions.Add(new RolePermission { RoleId = roleId, PermissionId = "*" });
                        }
                    }

                    _logger.LogInformation(
                        "Role {RoleId} created with {PermissionCount} permissions",
                        roleId, role.RolePermissions.Count);

                    try
                    {
                        await _roleRepository.CreateAsync(role, ct);
                    }
                    catch (Microsoft.EntityFrameworkCore.DbUpdateException ex) when (ex.InnerException is Npgsql.PostgresException { SqlState: "23505" })
                    {
                        _logger.LogInformation(
                            "Role {RoleId} already created by another process",
                            roleId);
                    }
                    catch (InvalidOperationException ex) when (ex.Message.Contains("already being tracked"))
                    {
                        _logger.LogInformation(
                            "Role {RoleId} is already being tracked by the context. Continuing to assignment.",
                            roleId);

                        // Use the tracked version for subsequent operations
                        role = _roleRepository.GetTracked(roleId) ?? role;
                    }
                }

                // Bind role to principal
                var existingBinding = await _bindingRepository.ExistsAsync(principalId, roleId, "*", ct);
                if (!existingBinding)
                {
                    var binding = new PrincipalRoleBinding
                    {
                        BindingId = Guid.NewGuid(),
                        PrincipalId = principalId,
                        RoleId = roleId,
                        ResourcePath = "*",
                        GrantedBy = IAMDbContext.SystemPrincipalId,
                        GrantedAt = DateTime.UtcNow
                    };

                    try
                    {
                        await _bindingRepository.CreateAsync(binding, ct);
                        _logger.LogInformation(
                            "Successfully granted {RoleId} to principal {PrincipalId}",
                            roleId, principalId);

                        // Clear permission cache to ensure fresh permissions are fetched on next request
                        var cacheKey = $"iam:principal:{principalId}:permissions";
                        await _cacheService.RemoveAsync(cacheKey, ct);
                        _logger.LogInformation(
                            "Cleared permission cache for principal {PrincipalId} after granting {RoleId}",
                            principalId, roleId);
                    }
                    catch (Microsoft.EntityFrameworkCore.DbUpdateException ex) when (ex.InnerException is Npgsql.PostgresException { SqlState: "23505" })
                    {
                        _logger.LogInformation(
                            "Binding for {RoleId} to {PrincipalId} already exists",
                            roleId, principalId);

                        // Clear cache anyway - the binding exists so permissions should be refreshed
                        var cacheKey = $"iam:principal:{principalId}:permissions";
                        await _cacheService.RemoveAsync(cacheKey, ct);
                        _logger.LogInformation(
                            "Cleared permission cache for principal {PrincipalId} (binding already existed)",
                            principalId);
                    }
                }

                success = true;  // Role created and bound successfully
            }
            catch (OperationCanceledException)
            {
                throw;  // Respect cancellation
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Attempt {Attempt}/{MaxRetries}: Failed to create/assign role {RoleId}",
                    attempt + 1, maxRetries, roleId);

                if (attempt < maxRetries - 1)
                {
                    var delay = (int)Math.Pow(2, attempt) * 1000;
                    await Task.Delay(delay, ct);
                    attempt++;
                }
                else
                {
                    throw;  // Give up after max retries
                }
            }
        }
    }

    private class TransientBootstrappingException(string message) : Exception(message);
}
