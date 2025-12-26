using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

public interface IServiceAccountApiKeyRepository
{
    Task<ServiceAccountApiKey?> GetByIdAsync(Guid keyId, CancellationToken cancellationToken = default);
    Task<ServiceAccountApiKey?> GetByPrefixAsync(string keyPrefix, CancellationToken cancellationToken = default);
    Task<IEnumerable<ServiceAccountApiKey>> GetByPrincipalIdAsync(Guid principalId, CancellationToken cancellationToken = default);
    Task<ServiceAccountApiKey> CreateAsync(ServiceAccountApiKey apiKey, CancellationToken cancellationToken = default);
    Task UpdateAsync(ServiceAccountApiKey apiKey, CancellationToken cancellationToken = default);
    Task DeactivateAsync(Guid keyId, CancellationToken cancellationToken = default);
    Task DeactivateByPrincipalIdAsync(Guid principalId, CancellationToken cancellationToken = default);
}
