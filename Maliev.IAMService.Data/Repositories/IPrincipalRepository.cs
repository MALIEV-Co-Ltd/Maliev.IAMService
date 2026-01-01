using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

/// <summary>
/// Interface for repository operations related to principals.
/// </summary>
public interface IPrincipalRepository
{
    /// <summary>
    /// Retrieves a principal by its unique identifier asynchronously.
    /// </summary>
    /// <param name="principalId">The unique identifier of the principal.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The principal if found; otherwise, null.</returns>
    Task<Principal?> GetByIdAsync(Guid principalId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a principal by its email address asynchronously.
    /// </summary>
    /// <param name="email">The email address of the principal.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The principal if found; otherwise, null.</returns>
    Task<Principal?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a principal linked to an external entity asynchronously.
    /// </summary>
    /// <param name="linkedService">The name of the linked service.</param>
    /// <param name="linkedEntityId">The unique identifier of the linked entity.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The principal if found; otherwise, null.</returns>
    Task<Principal?> GetByLinkedEntityAsync(string linkedService, Guid linkedEntityId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all principals asynchronously.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of all principals.</returns>
    Task<IEnumerable<Principal>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new principal asynchronously.
    /// </summary>
    /// <param name="principal">The principal to create.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The created principal.</returns>
    Task<Principal> CreateAsync(Principal principal, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing principal asynchronously.
    /// </summary>
    /// <param name="principal">The principal to update.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task UpdateAsync(Principal principal, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a principal by its unique identifier asynchronously.
    /// </summary>
    /// <param name="principalId">The unique identifier of the principal.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task DeleteAsync(Guid principalId, CancellationToken cancellationToken = default);
}
