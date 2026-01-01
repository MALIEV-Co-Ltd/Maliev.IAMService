using Microsoft.EntityFrameworkCore;
using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

/// <summary>
/// Repository implementation for permission operations.
/// </summary>
public class PermissionRepository : IPermissionRepository
{
    private readonly IAMDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="PermissionRepository"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public PermissionRepository(IAMDbContext context) => _context = context;

    /// <inheritdoc/>
    public async Task<Permission?> GetByIdAsync(string permissionId, CancellationToken cancellationToken = default) =>
        await _context.Permissions.FindAsync(new object[] { permissionId }, cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<Permission>> GetAllAsync(CancellationToken cancellationToken = default) =>
        await _context.Permissions.ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<Permission>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default) =>
        await _context.Permissions.Where(p => p.ServiceName == serviceName).ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<Permission>> GetByIdsAsync(IEnumerable<string> permissionIds, CancellationToken cancellationToken = default) =>
        await _context.Permissions.Where(p => permissionIds.Contains(p.PermissionId)).ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task<Permission> CreateAsync(Permission permission, CancellationToken cancellationToken = default)
    {
        _context.Permissions.Add(permission);
        await _context.SaveChangesAsync(cancellationToken);
        return permission;
    }

    /// <inheritdoc/>
    public async Task CreateManyAsync(IEnumerable<Permission> permissions, CancellationToken cancellationToken = default)
    {
        _context.Permissions.AddRange(permissions);
        await _context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<bool> ExistsAsync(string permissionId, CancellationToken cancellationToken = default) =>
        await _context.Permissions.AnyAsync(p => p.PermissionId == permissionId, cancellationToken);
}
