using Microsoft.EntityFrameworkCore;
using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

public class PermissionRepository : IPermissionRepository
{
    private readonly IAMDbContext _context;

    public PermissionRepository(IAMDbContext context) => _context = context;

    public async Task<Permission?> GetByIdAsync(string permissionId, CancellationToken cancellationToken = default) =>
        await _context.Permissions.FindAsync(new object[] { permissionId }, cancellationToken);

    public async Task<IEnumerable<Permission>> GetAllAsync(CancellationToken cancellationToken = default) =>
        await _context.Permissions.ToListAsync(cancellationToken);

    public async Task<IEnumerable<Permission>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default) =>
        await _context.Permissions.Where(p => p.ServiceName == serviceName).ToListAsync(cancellationToken);

    public async Task<IEnumerable<Permission>> GetByIdsAsync(IEnumerable<string> permissionIds, CancellationToken cancellationToken = default) =>
        await _context.Permissions.Where(p => permissionIds.Contains(p.PermissionId)).ToListAsync(cancellationToken);

    public async Task<Permission> CreateAsync(Permission permission, CancellationToken cancellationToken = default)
    {
        _context.Permissions.Add(permission);
        await _context.SaveChangesAsync(cancellationToken);
        return permission;
    }

    public async Task CreateManyAsync(IEnumerable<Permission> permissions, CancellationToken cancellationToken = default)
    {
        _context.Permissions.AddRange(permissions);
        await _context.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> ExistsAsync(string permissionId, CancellationToken cancellationToken = default) =>
        await _context.Permissions.AnyAsync(p => p.PermissionId == permissionId, cancellationToken);
}
