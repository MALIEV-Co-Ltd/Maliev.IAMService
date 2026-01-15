using Maliev.IAMService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Maliev.IAMService.Data;

/// <summary>
/// Database seeder for IAM Service in development/testing environments.
/// </summary>
public class DatabaseSeeder
{
    private readonly IAMDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly ILogger<DatabaseSeeder> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="DatabaseSeeder"/> class.
    /// </summary>
    public DatabaseSeeder(
        IAMDbContext context,
        IConfiguration configuration,
        ILogger<DatabaseSeeder> logger)
    {
        _context = context;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Seeds test principal with Employee role for testing purposes.
    /// Test credentials are loaded from user secrets or environment variables.
    /// </summary>
    public async Task SeedTestPrincipalAsync()
    {
        // Read from configuration (user secrets in dev, environment variables in production)
        var testEmail = _configuration["TestUser:Email"];
        var testPrincipalId = _configuration["TestUser:PrincipalId"];
        var testDisplayName = _configuration["TestUser:DisplayName"];
        var linkedService = _configuration["TestUser:LinkedService"] ?? "EmployeeService";

        if (string.IsNullOrEmpty(testEmail) || string.IsNullOrEmpty(testPrincipalId))
        {
            _logger.LogWarning("Test user configuration not found in secrets, skipping seed");
            return;
        }

        if (string.IsNullOrEmpty(testDisplayName))
        {
            _logger.LogWarning("TestUser:DisplayName not configured, using email as display name");
            testDisplayName = testEmail;
        }

        var principalGuid = Guid.Parse(testPrincipalId);

        try
        {
            // Check if principal already exists
            if (await _context.Principals.AnyAsync(p => p.PrincipalId == principalGuid))
            {
                _logger.LogInformation("Test principal {PrincipalId} already exists, skipping seed", principalGuid);
                return;
            }

            _logger.LogInformation("Seeding test principal for {Email}...", testEmail);

            // 1. Create Principal
            var principal = new Principal
            {
                PrincipalId = principalGuid,
                PrincipalType = "user",
                Email = testEmail,
                DisplayName = testDisplayName,
                IsActive = true,
                LinkedService = linkedService,
                LinkedEntityId = null, // Will be set by EmployeeService after employee creation
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            await _context.Principals.AddAsync(principal);
            await _context.SaveChangesAsync();

            // 2. Ensure Employee role exists
            const string employeeRoleId = "roles.employee.employee";
            var employeeRole = await _context.Roles.FirstOrDefaultAsync(r => r.RoleId == employeeRoleId);

            if (employeeRole == null)
            {
                _logger.LogInformation("Creating Employee role...");

                employeeRole = new Role
                {
                    RoleId = employeeRoleId,
                    RoleName = "Employee",
                    Description = "Basic employee role with profile read/update permissions",
                    ServiceName = "employee",
                    IsCustom = false,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                await _context.Roles.AddAsync(employeeRole);

                // Add role permissions
                var permissions = new[]
                {
                    "employee.profiles.read",
                    "employee.profiles.update"
                };

                foreach (var permissionId in permissions)
                {
                    // Ensure permission exists
                    if (!await _context.Permissions.AnyAsync(p => p.PermissionId == permissionId))
                    {
                        var parts = permissionId.Split('.');
                        await _context.Permissions.AddAsync(new Permission
                        {
                            PermissionId = permissionId,
                            ServiceName = parts[0],
                            ResourceType = parts[1],
                            Action = parts[2],
                            Description = $"{parts[2]} {parts[1]} in {parts[0]} service",
                            RegisteredAt = DateTime.UtcNow
                        });
                    }

                    await _context.RolePermissions.AddAsync(new RolePermission
                    {
                        RoleId = employeeRoleId,
                        PermissionId = permissionId,
                        AddedAt = DateTime.UtcNow
                    });
                }

                await _context.SaveChangesAsync();
            }

            // 3. Assign Employee role to test principal
            var binding = new PrincipalRoleBinding
            {
                BindingId = Guid.NewGuid(),
                PrincipalId = principalGuid,
                RoleId = employeeRoleId,
                GrantedBy = Guid.Empty, // System-granted
                GrantedAt = DateTime.UtcNow,
                ResourcePath = null // Global role, not resource-scoped
            };

            await _context.PrincipalRoleBindings.AddAsync(binding);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Successfully seeded test principal {PrincipalId} with Employee role", principalGuid);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error seeding test principal");
            throw;
        }
    }

    /// <summary>
    /// Seeds platform owner role and assigns it to the company owner.
    /// </summary>
    public async Task SeedPlatformOwnerAsync()
    {
        const string platformOwnerRoleId = "roles.platform.owner";
        var ownerEmail = "natthapol.vanasrivilai@maliev.com";

        try
        {
            // 1. Ensure Platform Owner role exists
            var platformOwnerRole = await _context.Roles.FirstOrDefaultAsync(r => r.RoleId == platformOwnerRoleId);
            if (platformOwnerRole == null)
            {
                _logger.LogInformation("Creating Platform Owner role...");
                platformOwnerRole = new Role
                {
                    RoleId = platformOwnerRoleId,
                    RoleName = "Platform Owner",
                    Description = "Ultimate platform owner with full access to all services and resources",
                    ServiceName = "iam",
                    IsCustom = false,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };
                await _context.Roles.AddAsync(platformOwnerRole);
                await _context.SaveChangesAsync();
            }

            // 2. Assign all IAM permissions to this role
            // In a real system, we might want to assign ALL permissions from ALL services.
            // For now, we'll assign all IAM permissions.
            var iamPermissions = await _context.Permissions.Where(p => p.ServiceName == "iam").ToListAsync();
            foreach (var permission in iamPermissions)
            {
                if (!await _context.RolePermissions.AnyAsync(rp => rp.RoleId == platformOwnerRoleId && rp.PermissionId == permission.PermissionId))
                {
                    await _context.RolePermissions.AddAsync(new RolePermission
                    {
                        RoleId = platformOwnerRoleId,
                        PermissionId = permission.PermissionId,
                        AddedAt = DateTime.UtcNow
                    });
                }
            }
            await _context.SaveChangesAsync();

            // 3. Find Natthapol's principal and assign the role
            var ownerPrincipal = await _context.Principals.FirstOrDefaultAsync(p => p.Email == ownerEmail);
            if (ownerPrincipal != null)
            {
                if (!await _context.PrincipalRoleBindings.AnyAsync(b => b.PrincipalId == ownerPrincipal.PrincipalId && b.RoleId == platformOwnerRoleId))
                {
                    await _context.PrincipalRoleBindings.AddAsync(new PrincipalRoleBinding
                    {
                        BindingId = Guid.NewGuid(),
                        PrincipalId = ownerPrincipal.PrincipalId,
                        RoleId = platformOwnerRoleId,
                        GrantedBy = Guid.Empty,
                        GrantedAt = DateTime.UtcNow
                    });
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Assigned Platform Owner role to {Email}", ownerEmail);
                }
            }
            else
            {
                _logger.LogWarning("Owner principal for {Email} not found, cannot assign platform owner role. Login via Google SSO first.", ownerEmail);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error seeding platform owner role");
            throw;
        }
    }

    /// <summary>
    /// Seeds system service accounts for core platform communication.
    /// </summary>
    public async Task SeedSystemServicesAsync()
    {
        const string authServiceName = "auth";
        var authEmail = $"{authServiceName}@serviceaccount.maliev.local";

        try
        {
            // 1. Ensure 'iam.auth.resolve-permissions' permission exists
            const string resolvePermId = "iam.auth.resolve-permissions";
            if (!await _context.Permissions.AnyAsync(p => p.PermissionId == resolvePermId))
            {
                _context.Permissions.Add(new Permission
                {
                    PermissionId = resolvePermId,
                    ServiceName = "iam",
                    ResourceType = "auth",
                    Action = "resolve-permissions",
                    Description = "Resolve effective permissions for a principal",
                    RegisteredAt = DateTime.UtcNow
                });
                await _context.SaveChangesAsync();
            }

            // 2. Ensure Auth Service principal exists
            var authPrincipal = await _context.Principals.FirstOrDefaultAsync(p => p.Email == authEmail);
            if (authPrincipal == null)
            {
                authPrincipal = new Principal
                {
                    PrincipalId = Guid.NewGuid(),
                    PrincipalType = "service_account",
                    Email = authEmail,
                    DisplayName = "Auth Service Account",
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };
                _context.Principals.Add(authPrincipal);
                await _context.SaveChangesAsync();
            }

            // 3. Ensure Auth Service system role exists
            const string authRoleId = "roles.system.auth-service";
            if (!await _context.Roles.AnyAsync(r => r.RoleId == authRoleId))
            {
                var role = new Role
                {
                    RoleId = authRoleId,
                    RoleName = "Auth Service System Role",
                    Description = "Internal role for Auth Service to resolve permissions",
                    ServiceName = "system",
                    IsCustom = false,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };
                _context.Roles.Add(role);

                _context.RolePermissions.Add(new RolePermission
                {
                    RoleId = authRoleId,
                    PermissionId = resolvePermId,
                    AddedAt = DateTime.UtcNow
                });
                await _context.SaveChangesAsync();
            }

            // 4. Bind role to principal
            if (!await _context.PrincipalRoleBindings.AnyAsync(b => b.PrincipalId == authPrincipal.PrincipalId && b.RoleId == authRoleId))
            {
                _context.PrincipalRoleBindings.Add(new PrincipalRoleBinding
                {
                    BindingId = Guid.NewGuid(),
                    PrincipalId = authPrincipal.PrincipalId,
                    RoleId = authRoleId,
                    GrantedBy = Guid.Empty,
                    GrantedAt = DateTime.UtcNow
                });
                await _context.SaveChangesAsync();
                _logger.LogInformation("Successfully seeded auth-service system permissions");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error seeding system services");
            throw;
        }
    }

    /// <summary>
    /// Seeds geometry-service principal for integration tests.
    /// </summary>
    public async Task SeedGeometryServiceAsync()
    {
        const string serviceName = "geometry-service";
        var email = $"{serviceName}@serviceaccount.maliev.local";

        try
        {
            // 1. Seed the permission first to satisfy FK constraint
            const string permissionId = "upload.files.upload";
            if (!await _context.Permissions.AnyAsync(p => p.PermissionId == permissionId))
            {
                _context.Permissions.Add(new Permission
                {
                    PermissionId = permissionId,
                    ServiceName = "upload",
                    ResourceType = "files",
                    Action = "upload",
                    Description = "Upload files (Seed)",
                    RegisteredAt = DateTime.UtcNow
                });
                await _context.SaveChangesAsync();
            }

            // 2. Seed the principal
            if (!await _context.Principals.AnyAsync(p => p.Email == email))
            {
                var principalId = Guid.NewGuid();
                _context.Principals.Add(new Principal
                {
                    PrincipalId = principalId,
                    PrincipalType = "service_account",
                    Email = email,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                });

                // 3. Grant upload.files.upload permission via a direct role binding
                const string roleId = "roles.system.geometry-service";
                if (!await _context.Roles.AnyAsync(r => r.RoleId == roleId))
                {
                    var role = new Role
                    {
                        RoleId = roleId,
                        RoleName = "Geometry Service Role",
                        Description = "System role for geometry service",
                        ServiceName = "system",
                        IsCustom = false,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow
                    };
                    _context.Roles.Add(role);

                    _context.RolePermissions.Add(new RolePermission
                    {
                        RoleId = roleId,
                        PermissionId = permissionId,
                        AddedAt = DateTime.UtcNow
                    });
                }

                _context.PrincipalRoleBindings.Add(new PrincipalRoleBinding
                {
                    BindingId = Guid.NewGuid(),
                    PrincipalId = principalId,
                    RoleId = roleId,
                    GrantedBy = Guid.Empty,
                    GrantedAt = DateTime.UtcNow
                });

                await _context.SaveChangesAsync();
                _logger.LogInformation("Successfully seeded geometry-service principal");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error seeding geometry-service principal");
            throw;
        }
    }

    /// <summary>
    /// Seeds all development data including test users and system service accounts.
    /// </summary>
    public async Task SeedDevelopmentDataAsync()
    {
        await SeedTestPrincipalAsync();
        await SeedPlatformOwnerAsync();
        await SeedSystemServicesAsync();
        await SeedGeometryServiceAsync();
    }

    /// <summary>
    /// Seeds all development data.
    /// </summary>
    public async Task SeedAllAsync()
    {
        await SeedDevelopmentDataAsync();
    }
}
