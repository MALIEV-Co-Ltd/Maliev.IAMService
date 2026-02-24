using Maliev.IAMService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Maliev.IAMService.Data.Repositories;

/// <summary>
/// Repository implementation for role operations.
/// </summary>
public class RoleRepository : IRoleRepository
{
    private readonly IAMDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="RoleRepository"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public RoleRepository(IAMDbContext context) => _context = context;

    /// <inheritdoc/>
    public async Task<Role?> GetByIdAsync(string roleId, CancellationToken cancellationToken = default) =>
        await _context.Roles.Include(r => r.RolePermissions).ThenInclude(rp => rp.Permission)
            .FirstOrDefaultAsync(r => r.RoleId == roleId, cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<Role>> GetAllAsync(CancellationToken cancellationToken = default) =>
        await _context.Roles.Include(r => r.RolePermissions).ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<Role>> GetByIdsAsync(IEnumerable<string> roleIds, CancellationToken cancellationToken = default) =>
        await _context.Roles.Where(r => roleIds.Contains(r.RoleId)).ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<RolePermission>> GetPermissionsForRolesAsync(IEnumerable<string> roleIds, CancellationToken cancellationToken = default) =>
        await _context.RolePermissions
            .Where(rp => roleIds.Contains(rp.RoleId))
            .Include(rp => rp.Permission)
            .ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<Role>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default) =>
        await _context.Roles.Where(r => r.ServiceName == serviceName).ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<Role>> GetCustomRolesAsync(CancellationToken cancellationToken = default) =>
        await _context.Roles.Where(r => r.IsCustom).ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task<Role> CreateAsync(Role role, CancellationToken cancellationToken = default)
    {
        // Same rationale as CreateManyAsync: raw SQL ON CONFLICT DO NOTHING avoids the EF Core
        // exception logging path that fires before the catch block on concurrent duplicate inserts.
        await _context.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO roles (role_id, role_name, service_name, description, is_custom, created_by, created_at, updated_at)
            VALUES ({role.RoleId}, {role.RoleName}, {role.ServiceName}, {role.Description}, {role.IsCustom}, {role.CreatedBy}, {role.CreatedAt}, {role.UpdatedAt})
            ON CONFLICT (role_id) DO NOTHING
            """,
            cancellationToken);

        foreach (var rp in role.RolePermissions)
        {
            await _context.Database.ExecuteSqlAsync(
                $"""
                INSERT INTO role_permissions (role_id, permission_id, added_at)
                VALUES ({rp.RoleId}, {rp.PermissionId}, {rp.AddedAt})
                ON CONFLICT (role_id, permission_id) DO NOTHING
                """,
                cancellationToken);
        }

        return await _context.Roles
            .Include(r => r.RolePermissions)
            .FirstAsync(r => r.RoleId == role.RoleId, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task CreateManyAsync(IEnumerable<Role> roles, CancellationToken cancellationToken = default)
    {
        var roleList = roles.ToList();
        if (!roleList.Any()) return;

        // Raw SQL with ON CONFLICT DO NOTHING is used here instead of EF Core Add+SaveChanges.
        // During startup, multiple services call RegisterRoles concurrently (up to 5 at once due to the
        // semaphore in RoleService). All concurrent requests can read an empty DB simultaneously (TOCTOU),
        // then all attempt to insert the same roles. With EF Core, this causes DbUpdateException(23505)
        // which EF Core logs at "fail" level internally before the catch block fires — polluting logs even
        // though the exception was handled. ON CONFLICT DO NOTHING is atomic at the DB level and never
        // enters the EF Core exception path, so the race is handled cleanly with no error logs.
        foreach (var role in roleList)
        {
            await _context.Database.ExecuteSqlAsync(
                $"""
                INSERT INTO roles (role_id, role_name, service_name, description, is_custom, created_by, created_at, updated_at)
                VALUES ({role.RoleId}, {role.RoleName}, {role.ServiceName}, {role.Description}, {role.IsCustom}, {role.CreatedBy}, {role.CreatedAt}, {role.UpdatedAt})
                ON CONFLICT (role_id) DO NOTHING
                """,
                cancellationToken);

            foreach (var rp in role.RolePermissions)
            {
                await _context.Database.ExecuteSqlAsync(
                    $"""
                    INSERT INTO role_permissions (role_id, permission_id, added_at)
                    VALUES ({rp.RoleId}, {rp.PermissionId}, {rp.AddedAt})
                    ON CONFLICT (role_id, permission_id) DO NOTHING
                    """,
                    cancellationToken);
            }
        }
    }

    /// <inheritdoc/>
    public async Task UpdateAsync(Role role, CancellationToken cancellationToken = default)
    {
        role.UpdatedAt = DateTime.UtcNow;
        _context.Roles.Update(role);
        try
        {
            await _context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException pgEx && pgEx.SqlState == "23505")
        {
            _context.Entry(role).State = EntityState.Detached;
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task DeleteAsync(string roleId, CancellationToken cancellationToken = default)
    {
        var role = await _context.Roles.FindAsync(new object[] { roleId }, cancellationToken);
        if (role != null)
        {
            _context.Roles.Remove(role);
            await _context.SaveChangesAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
    public async Task<bool> HasActiveBindingsAsync(string roleId, CancellationToken cancellationToken = default) =>
        await _context.PrincipalRoleBindings.AnyAsync(prb => prb.RoleId == roleId, cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<Permission>> GetRolePermissionsAsync(string roleId, CancellationToken cancellationToken = default)
    {
        var rolePermissions = await _context.RolePermissions
            .Where(rp => rp.RoleId == roleId)
            .Include(rp => rp.Permission)
            .ToListAsync(cancellationToken);

        return rolePermissions.Select(rp => rp.Permission);
    }

    /// <inheritdoc/>
    public async Task<bool> AddPermissionToRoleAsync(string roleId, string permissionId, CancellationToken cancellationToken = default)
    {
        var rows = await _context.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO role_permissions (role_id, permission_id, added_at)
            VALUES ({roleId}, {permissionId}, {DateTime.UtcNow})
            ON CONFLICT (role_id, permission_id) DO NOTHING
            """,
            cancellationToken);
        return rows > 0;
    }

    /// <inheritdoc/>
    public Role? GetTracked(string roleId) =>
        _context.Roles.Local.FirstOrDefault(r => r.RoleId == roleId);
}
