using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

public interface IBindingRepository
{
    Task<PrincipalRoleBinding?> GetByIdAsync(Guid bindingId, CancellationToken cancellationToken = default);
    Task<IEnumerable<PrincipalRoleBinding>> GetByPrincipalAsync(Guid principalId, CancellationToken cancellationToken = default);
    Task<PrincipalRoleBinding> CreateAsync(PrincipalRoleBinding binding, CancellationToken cancellationToken = default);
    Task DeleteAsync(Guid bindingId, CancellationToken cancellationToken = default);
    Task<bool> ExistsAsync(Guid principalId, string roleId, string? resourcePath, CancellationToken cancellationToken = default);
    Task<IEnumerable<PrincipalRoleBinding>> GetExpiredBindingsAsync(CancellationToken cancellationToken = default);
    Task DeleteExpiredBindingsAsync(CancellationToken cancellationToken = default);
}
