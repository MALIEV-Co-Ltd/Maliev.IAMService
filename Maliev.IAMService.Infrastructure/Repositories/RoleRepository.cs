using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Application.Workloads;
using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Maliev.IAMService.Infrastructure.Repositories;

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
        EnsureRoleIsNotWorkloadManaged(role.RoleId);
        _context.Roles.Add(role);
        try
        {
            await _context.SaveChangesAsync(cancellationToken);
            return role;
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException pgEx && pgEx.SqlState == "23505")
        {
            _context.Entry(role).State = EntityState.Detached;
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task CreateManyAsync(IEnumerable<Role> roles, CancellationToken cancellationToken = default)
    {
        var roleList = roles.ToList();
        if (!roleList.Any()) return;
        foreach (var role in roleList)
            EnsureRoleIsNotWorkloadManaged(role.RoleId);

        await _context.Roles.AddRangeAsync(roleList, cancellationToken);
        try
        {
            await _context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException pgEx && pgEx.SqlState == "23505")
        {
            // Detach ALL tracked entities — both parent Role and child RolePermission rows.
            // Failing to detach children leaves orphaned RolePermission entries in the
            // change tracker which then cause duplicate-key violations on the per-row retry.
            foreach (var r in roleList)
            {
                foreach (var rp in r.RolePermissions.ToList())
                    _context.Entry(rp).State = EntityState.Detached;
                _context.Entry(r).State = EntityState.Detached;
            }

            // Retry one-by-one, skipping roles that already exist.
            foreach (var role in roleList)
            {
                await _context.Roles.AddAsync(role, cancellationToken);
                try
                {
                    await _context.SaveChangesAsync(cancellationToken);
                }
                catch (DbUpdateException innerEx) when (innerEx.InnerException is PostgresException innerPgEx && innerPgEx.SqlState == "23505")
                {
                    foreach (var rp in role.RolePermissions.ToList())
                        _context.Entry(rp).State = EntityState.Detached;
                    _context.Entry(role).State = EntityState.Detached;
                }
            }
        }
    }

    /// <inheritdoc/>
    public async Task UpdateAsync(Role role, CancellationToken cancellationToken = default)
    {
        EnsureRoleIsNotWorkloadManaged(role.RoleId);
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
        EnsureRoleIsNotWorkloadManaged(roleId);
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
    public Role? GetTracked(string roleId) =>
        _context.Roles.Local.FirstOrDefault(r => r.RoleId == roleId);

    private static void EnsureRoleIsNotWorkloadManaged(string roleId)
    {
        if (roleId.StartsWith("roles.workloads.", StringComparison.Ordinal))
            throw new ManagedWorkloadMutationException("Server-owned workload roles can only be changed by workload provisioning.");
    }
}
