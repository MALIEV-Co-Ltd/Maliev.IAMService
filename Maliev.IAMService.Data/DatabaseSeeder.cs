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

        if (string.IsNullOrEmpty(testEmail) || string.IsNullOrEmpty(testPrincipalId))
        {
            _logger.LogWarning("Test user configuration not found in secrets, skipping seed");
            return;
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
                DisplayName = "Natthapol Vanasrivilai",
                IsActive = true,
                LinkedService = "EmployeeService",
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
    /// Seeds all development data.
    /// </summary>
    public async Task SeedAllAsync()
    {
        await SeedTestPrincipalAsync();
    }
}
