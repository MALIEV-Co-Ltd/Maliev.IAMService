using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

/// <summary>
/// Interface for repository operations related to service account API keys.
/// </summary>
public interface IServiceAccountApiKeyRepository
{
    /// <summary>
    /// Retrieves an API key by its unique identifier asynchronously.
    /// </summary>
    /// <param name="keyId">The unique identifier of the API key.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The API key if found; otherwise, null.</returns>
    Task<ServiceAccountApiKey?> GetByIdAsync(Guid keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves an API key by its prefix asynchronously.
    /// </summary>
    /// <param name="keyPrefix">The prefix of the API key.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The API key if found; otherwise, null.</returns>
    Task<ServiceAccountApiKey?> GetByPrefixAsync(string keyPrefix, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all API keys associated with a specific principal asynchronously.
    /// </summary>
    /// <param name="principalId">The unique identifier of the principal.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of API keys.</returns>
    Task<IEnumerable<ServiceAccountApiKey>> GetByPrincipalIdAsync(Guid principalId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new API key asynchronously.
    /// </summary>
    /// <param name="apiKey">The API key to create.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The created API key.</returns>
    Task<ServiceAccountApiKey> CreateAsync(ServiceAccountApiKey apiKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing API key asynchronously.
    /// </summary>
    /// <param name="apiKey">The API key to update.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task UpdateAsync(ServiceAccountApiKey apiKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deactivates an API key by its unique identifier asynchronously.
    /// </summary>
    /// <param name="keyId">The unique identifier of the API key.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task DeactivateAsync(Guid keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deactivates all API keys for a specific principal asynchronously.
    /// </summary>
    /// <param name="principalId">The unique identifier of the principal.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task DeactivateByPrincipalIdAsync(Guid principalId, CancellationToken cancellationToken = default);
}
