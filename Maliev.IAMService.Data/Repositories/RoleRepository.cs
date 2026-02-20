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

        await _context.Roles.AddRangeAsync(roleList, cancellationToken);
        try
        {
            await _context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException pgEx && pgEx.SqlState == "23505")
        {
            foreach (var r in roleList)
                _context.Entry(r).State = EntityState.Detached;

            foreach (var role in roleList)
            {
                await _context.Roles.AddAsync(role, cancellationToken);
                try
                {
                    await _context.SaveChangesAsync(cancellationToken);
                }
                catch (DbUpdateException innerEx) when (innerEx.InnerException is PostgresException innerPgEx && innerPgEx.SqlState == "23505")
                {
                    _context.Entry(role).State = EntityState.Detached;
                }
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
    public Role? GetTracked(string roleId) =>
        _context.Roles.Local.FirstOrDefault(r => r.RoleId == roleId);
}
