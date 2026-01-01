using Microsoft.EntityFrameworkCore;
using Maliev.IAMService.Data.Entities;

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
    public async Task<IEnumerable<Role>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default) =>
        await _context.Roles.Where(r => r.ServiceName == serviceName).ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<Role>> GetCustomRolesAsync(CancellationToken cancellationToken = default) =>
        await _context.Roles.Where(r => r.IsCustom).ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task<Role> CreateAsync(Role role, CancellationToken cancellationToken = default)
    {
        _context.Roles.Add(role);
        await _context.SaveChangesAsync(cancellationToken);
        return role;
    }

    /// <inheritdoc/>
    public async Task UpdateAsync(Role role, CancellationToken cancellationToken = default)
    {
        role.UpdatedAt = DateTime.UtcNow;
        _context.Roles.Update(role);
        await _context.SaveChangesAsync(cancellationToken);
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
}
