using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

/// <summary>
/// Interface for repository operations related to principal-role bindings.
/// </summary>
public interface IBindingRepository
{
    /// <summary>
    /// Retrieves a binding by its unique identifier asynchronously.
    /// </summary>
    /// <param name="bindingId">The unique identifier of the binding.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The binding if found; otherwise, null.</returns>
    Task<PrincipalRoleBinding?> GetByIdAsync(Guid bindingId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all bindings associated with a specific principal asynchronously.
    /// </summary>
    /// <param name="principalId">The unique identifier of the principal.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of bindings.</returns>
    Task<IEnumerable<PrincipalRoleBinding>> GetByPrincipalAsync(Guid principalId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new binding asynchronously.
    /// </summary>
    /// <param name="binding">The binding to create.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The created binding.</returns>
    Task<PrincipalRoleBinding> CreateAsync(PrincipalRoleBinding binding, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a binding by its unique identifier asynchronously.
    /// </summary>
    /// <param name="bindingId">The unique identifier of the binding.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task DeleteAsync(Guid bindingId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a binding exists for a specific principal, role, and resource path asynchronously.
    /// </summary>
    /// <param name="principalId">The unique identifier of the principal.</param>
    /// <param name="roleId">The unique identifier of the role.</param>
    /// <param name="resourcePath">The resource path.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if the binding exists; otherwise, false.</returns>
    Task<bool> ExistsAsync(Guid principalId, string roleId, string? resourcePath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all expired bindings asynchronously.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of expired bindings.</returns>
    Task<IEnumerable<PrincipalRoleBinding>> GetExpiredBindingsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes all expired bindings asynchronously.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task DeleteExpiredBindingsAsync(CancellationToken cancellationToken = default);
}
