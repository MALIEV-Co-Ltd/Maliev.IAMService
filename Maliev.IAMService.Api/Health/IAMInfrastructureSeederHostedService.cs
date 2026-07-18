using Maliev.IAMService.Infrastructure.Persistence;
using Maliev.IAMService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Maliev.IAMService.Api.Health;

/// <summary>
/// Seeds IAM database with essential infrastructure data on startup.
/// This ensures the IAM service is self-contained and doesn't rely on external seeders.
/// Seeds: system principal, wildcard permission, Platform Owner role, and bootstrap admin.
/// </summary>
public class IAMInfrastructureSeederHostedService : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<IAMInfrastructureSeederHostedService> _logger;

    private const string PlatformOwnerRoleId = "roles.platform.owner";
    private static readonly Guid SystemPrincipalId = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static readonly Guid LegacyBootstrapAdminId = Guid.Parse("00000000-0000-0000-0000-000000000002");

    /// <summary>
    /// Initializes a new instance of the <see cref="IAMInfrastructureSeederHostedService"/> class.
    /// </summary>
    /// <param name="serviceProvider">The service provider.</param>
    /// <param name="logger">The logger.</param>
    public IAMInfrastructureSeederHostedService(
        IServiceProvider serviceProvider,
        ILogger<IAMInfrastructureSeederHostedService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    /// <summary>
    /// Starts the infrastructure seeding process.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting IAM infrastructure seeding...");

        try
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();

            await dbContext.Database.MigrateAsync(cancellationToken);

            await SeedWildcardPermissionAsync(dbContext, cancellationToken);
            await SeedPlatformOwnerRoleAsync(dbContext, cancellationToken);
            await SeedSystemPrincipalAsync(dbContext, cancellationToken);
            await CleanupLegacyBootstrapAdminAsync(dbContext, cancellationToken);

            _logger.LogInformation("IAM infrastructure seeding completed successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to seed IAM infrastructure. The service may not function correctly.");
        }
    }

    /// <summary>
    /// Stops the hosted service.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private async Task SeedWildcardPermissionAsync(IAMDbContext dbContext, CancellationToken ct)
    {
        var existing = await dbContext.Permissions.FirstOrDefaultAsync(p => p.PermissionId == "*", ct);
        if (existing != null)
        {
            _logger.LogDebug("Wildcard permission already exists");
            return;
        }

        _logger.LogInformation("Creating wildcard permission");
        dbContext.Permissions.Add(new Permission
        {
            PermissionId = "*",
            ServiceName = "platform",
            ResourceType = "all",
            Action = "all",
            Description = "Wildcard permission for full access"
        });
        await dbContext.SaveChangesAsync(ct);
    }

    private async Task SeedPlatformOwnerRoleAsync(IAMDbContext dbContext, CancellationToken ct)
    {
        var existing = await dbContext.Roles.FirstOrDefaultAsync(r => r.RoleId == PlatformOwnerRoleId, ct);
        if (existing != null)
        {
            _logger.LogDebug("Platform Owner role already exists");
            return;
        }

        _logger.LogInformation("Creating Platform Owner role");
        dbContext.Roles.Add(new Role
        {
            RoleId = PlatformOwnerRoleId,
            RoleName = "Platform Owner",
            ServiceName = "platform",
            Description = "Full administrative access",
            IsCustom = false,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            RolePermissions = new List<RolePermission>
            {
                new RolePermission { RoleId = PlatformOwnerRoleId, PermissionId = "*" }
            }
        });
        await dbContext.SaveChangesAsync(ct);
    }

    private async Task SeedSystemPrincipalAsync(IAMDbContext dbContext, CancellationToken ct)
    {
        var existing = await dbContext.Principals
            .FirstOrDefaultAsync(p => p.Email == "system@maliev.com", ct);

        if (existing != null)
        {
            _logger.LogDebug("System principal already exists");
            return;
        }

        _logger.LogInformation("Creating system principal");
        dbContext.Principals.Add(new Principal
        {
            PrincipalId = SystemPrincipalId,
            Email = "system@maliev.com",
            DisplayName = "System Principal",
            PrincipalType = "system",
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        });
        await dbContext.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Removes the legacy seeded bootstrap admin (admin@maliev.com) that blocked real
    /// first-user provisioning. The EmployeeCreatedConsumer and BFF bootstrap/promote
    /// endpoint handle first-user Platform Owner grant correctly on their own.
    /// </summary>
    private async Task CleanupLegacyBootstrapAdminAsync(IAMDbContext dbContext, CancellationToken ct)
    {
        var existing = await dbContext.Principals
            .FirstOrDefaultAsync(p => p.PrincipalId == LegacyBootstrapAdminId, ct);

        if (existing == null)
            return;

        // Remove role bindings first (FK constraint)
        var bindings = await dbContext.PrincipalRoleBindings
            .Where(b => b.PrincipalId == LegacyBootstrapAdminId)
            .ToListAsync(ct);

        if (bindings.Count > 0)
        {
            dbContext.PrincipalRoleBindings.RemoveRange(bindings);
            _logger.LogInformation("Removing {Count} role binding(s) from legacy bootstrap admin", bindings.Count);
        }

        dbContext.Principals.Remove(existing);
        await dbContext.SaveChangesAsync(ct);
        _logger.LogInformation("Removed legacy bootstrap admin (admin@maliev.com) that was blocking first-user provisioning");
    }
}
