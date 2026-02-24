using Maliev.IAMService.Data;
using Maliev.IAMService.Data.Entities;
using Maliev.IAMService.Data.Repositories;
using Maliev.IAMService.Tests.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Integration tests for RoleRepository, specifically testing the idempotent
/// AddPermissionToRoleAsync method to ensure no duplicate key errors on concurrent calls.
/// </summary>
public class RoleRepositoryTests : BaseIntegrationTest
{
    public RoleRepositoryTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task AddPermissionToRoleAsync_NewPermission_ReturnsTrue()
    {
        await CleanDatabaseAsync();

        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();
        var roleRepository = scope.ServiceProvider.GetRequiredService<IRoleRepository>();

        // Arrange - Create role and permission
        var role = new Role
        {
            RoleId = "roles.test.add-permission",
            RoleName = "Test Role",
            ServiceName = "test",
            IsCustom = false
        };
        dbContext.Roles.Add(role);

        var permission = new Permission
        {
            PermissionId = "test.resource.action",
            ServiceName = "test",
            ResourceType = "resource",
            Action = "action",
            Description = "Test permission"
        };
        dbContext.Permissions.Add(permission);
        await dbContext.SaveChangesAsync();

        // Act
        var result = await roleRepository.AddPermissionToRoleAsync(role.RoleId, permission.PermissionId);

        // Assert
        Assert.True(result);

        var rolePermission = await dbContext.RolePermissions
            .FirstOrDefaultAsync(rp => rp.RoleId == role.RoleId && rp.PermissionId == permission.PermissionId);
        Assert.NotNull(rolePermission);
    }

    [Fact]
    public async Task AddPermissionToRoleAsync_ExistingPermission_ReturnsFalse()
    {
        await CleanDatabaseAsync();

        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();
        var roleRepository = scope.ServiceProvider.GetRequiredService<IRoleRepository>();

        // Arrange - Create role and permission with existing binding
        var role = new Role
        {
            RoleId = "roles.test.existing-permission",
            RoleName = "Test Role",
            ServiceName = "test",
            IsCustom = false
        };
        dbContext.Roles.Add(role);

        var permission = new Permission
        {
            PermissionId = "test.resource.existing",
            ServiceName = "test",
            ResourceType = "resource",
            Action = "existing",
            Description = "Test permission"
        };
        dbContext.Permissions.Add(permission);
        await dbContext.SaveChangesAsync();

        // Add existing binding
        dbContext.RolePermissions.Add(new RolePermission
        {
            RoleId = role.RoleId,
            PermissionId = permission.PermissionId
        });
        await dbContext.SaveChangesAsync();

        // Act - Try to add again
        var result = await roleRepository.AddPermissionToRoleAsync(role.RoleId, permission.PermissionId);

        // Assert
        Assert.False(result);

        // Verify only one binding exists
        var count = await dbContext.RolePermissions
            .CountAsync(rp => rp.RoleId == role.RoleId && rp.PermissionId == permission.PermissionId);
        Assert.Equal(1, count);
    }

    [Fact]
    public async Task AddPermissionToRoleAsync_ConcurrentCalls_NoDuplicateKeyErrors()
    {
        await CleanDatabaseAsync();

        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();

        // Arrange - Create role and permission
        var role = new Role
        {
            RoleId = "roles.test.concurrent",
            RoleName = "Concurrent Test Role",
            ServiceName = "test",
            IsCustom = false
        };
        dbContext.Roles.Add(role);

        var permission = new Permission
        {
            PermissionId = "test.resource.concurrent",
            ServiceName = "test",
            ResourceType = "resource",
            Action = "concurrent",
            Description = "Test permission for concurrency"
        };
        dbContext.Permissions.Add(permission);
        await dbContext.SaveChangesAsync();

        // Act - Simulate concurrent calls by creating multiple repository instances
        // Each will have its own DbContext (scoped lifestyle)
        var tasks = new List<Task<bool>>();
        for (int i = 0; i < 5; i++)
        {
            tasks.Add(Task.Run(async () =>
            {
                using var innerScope = Factory.Services.CreateScope();
                var innerRepo = innerScope.ServiceProvider.GetRequiredService<IRoleRepository>();
                return await innerRepo.AddPermissionToRoleAsync(role.RoleId, permission.PermissionId);
            }));
        }

        var results = await Task.WhenAll(tasks);

        // Assert - Exactly one should return true (the one that added the permission)
        Assert.Equal(1, results.Count(r => r == true));
        Assert.Equal(4, results.Count(r => r == false));

        // Verify only one binding exists in database
        var count = await dbContext.RolePermissions
            .CountAsync(rp => rp.RoleId == role.RoleId && rp.PermissionId == permission.PermissionId);
        Assert.Equal(1, count);
    }

    [Fact]
    public async Task AddPermissionToRoleAsync_NonExistentRole_ThrowsPostgresException()
    {
        await CleanDatabaseAsync();

        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();
        var roleRepository = scope.ServiceProvider.GetRequiredService<IRoleRepository>();

        // Arrange - Create only the permission, not the role
        var permission = new Permission
        {
            PermissionId = "test.resource.orphan",
            ServiceName = "test",
            ResourceType = "resource",
            Action = "orphan",
            Description = "Test permission"
        };
        dbContext.Permissions.Add(permission);
        await dbContext.SaveChangesAsync();

        // Act & Assert - Should throw FK constraint violation
        var ex = await Assert.ThrowsAsync<PostgresException>(
            () => roleRepository.AddPermissionToRoleAsync("roles.nonexistent", permission.PermissionId));

        // Verify it's an FK violation (23503)
        Assert.Equal("23503", ex.SqlState);
    }

    [Fact]
    public async Task AddPermissionToRoleAsync_NonExistentPermission_ThrowsPostgresException()
    {
        await CleanDatabaseAsync();

        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();
        var roleRepository = scope.ServiceProvider.GetRequiredService<IRoleRepository>();

        // Arrange - Create only the role, not the permission
        var role = new Role
        {
            RoleId = "roles.test.no-permission",
            RoleName = "Test Role",
            ServiceName = "test",
            IsCustom = false
        };
        dbContext.Roles.Add(role);
        await dbContext.SaveChangesAsync();

        // Act & Assert - Should throw FK constraint violation
        var ex = await Assert.ThrowsAsync<PostgresException>(
            () => roleRepository.AddPermissionToRoleAsync(role.RoleId, "nonexistent.permission.action"));

        // Verify it's an FK violation (23503)
        Assert.Equal("23503", ex.SqlState);
    }
}
