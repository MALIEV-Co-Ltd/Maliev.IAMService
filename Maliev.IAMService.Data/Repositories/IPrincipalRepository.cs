using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

public interface IPrincipalRepository
{
    Task<Principal?> GetByIdAsync(Guid principalId, CancellationToken cancellationToken = default);
    Task<Principal?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);
    Task<Principal?> GetByLinkedEntityAsync(string linkedService, Guid linkedEntityId, CancellationToken cancellationToken = default);
    Task<IEnumerable<Principal>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<Principal> CreateAsync(Principal principal, CancellationToken cancellationToken = default);
    Task UpdateAsync(Principal principal, CancellationToken cancellationToken = default);
    Task DeleteAsync(Guid principalId, CancellationToken cancellationToken = default);
}
