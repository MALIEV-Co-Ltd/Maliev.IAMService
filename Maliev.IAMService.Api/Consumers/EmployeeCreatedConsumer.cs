using Maliev.IAMService.Api.Services;
using Maliev.IAMService.Data;
using Maliev.IAMService.Data.Entities;
using Maliev.IAMService.Data.Repositories;
using Maliev.MessagingContracts.Contracts.Employee;
using MassTransit;
using Microsoft.EntityFrameworkCore;

namespace Maliev.IAMService.Api.Consumers;

/// <summary>
/// Consumer for EmployeeCreated events.
/// Automatically provisions a Principal in the IAM system for new employees.
/// Grants 'roles.iam.admin' with all permissions to the first user created to allow system bootstrapping.
/// </summary>
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
                _logger.LogInformation("Principal {PrincipalId} already exists, skipping provisioning.", payload.PrincipalId);
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

            // Check if this is the first non-system user to grant admin permissions
            // We ignore the pre-seeded admin@maliev.com when determining the first real user
            var allUsers = (await _principalRepository.GetAllAsync(context.CancellationToken)).ToList();
            var realUsers = allUsers.Where(p =>
                p.PrincipalType == "user" &&
                p.Email != "admin@maliev.com").ToList();

            bool isFirstRealUser = realUsers.Count == 1 && realUsers.First().PrincipalId == payload.PrincipalId;

            if (isFirstRealUser)
            {
                _logger.LogInformation("First real user detected ({Email}). Bootstrapping admin role.", payload.Email);
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

                    if (!filteredPermissions.Any())
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
