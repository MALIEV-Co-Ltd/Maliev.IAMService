using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

public interface IPermissionRepository
{
    Task<Permission?> GetByIdAsync(string permissionId, CancellationToken cancellationToken = default);
    Task<IEnumerable<Permission>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<IEnumerable<Permission>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default);
    Task<IEnumerable<Permission>> GetByIdsAsync(IEnumerable<string> permissionIds, CancellationToken cancellationToken = default);
    Task<Permission> CreateAsync(Permission permission, CancellationToken cancellationToken = default);
    Task CreateManyAsync(IEnumerable<Permission> permissions, CancellationToken cancellationToken = default);
    Task<bool> ExistsAsync(string permissionId, CancellationToken cancellationToken = default);
}
