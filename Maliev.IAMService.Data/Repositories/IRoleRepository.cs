using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

public interface IRoleRepository
{
    Task<Role?> GetByIdAsync(string roleId, CancellationToken cancellationToken = default);
    Task<IEnumerable<Role>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<IEnumerable<Role>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default);
    Task<IEnumerable<Role>> GetCustomRolesAsync(CancellationToken cancellationToken = default);
    Task<Role> CreateAsync(Role role, CancellationToken cancellationToken = default);
    Task UpdateAsync(Role role, CancellationToken cancellationToken = default);
    Task DeleteAsync(string roleId, CancellationToken cancellationToken = default);
    Task<bool> HasActiveBindingsAsync(string roleId, CancellationToken cancellationToken = default);
    Task<IEnumerable<Permission>> GetRolePermissionsAsync(string roleId, CancellationToken cancellationToken = default);
}
