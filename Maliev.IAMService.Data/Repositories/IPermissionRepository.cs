using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

/// <summary>
/// Interface for repository operations related to permissions.
/// </summary>
public interface IPermissionRepository
{
    /// <summary>
    /// Retrieves a permission by its unique identifier asynchronously.
    /// </summary>
    /// <param name="permissionId">The unique identifier of the permission.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The permission if found; otherwise, null.</returns>
    Task<Permission?> GetByIdAsync(string permissionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all permissions asynchronously.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of all permissions.</returns>
    Task<IEnumerable<Permission>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves permissions associated with a specific service asynchronously.
    /// </summary>
    /// <param name="serviceName">The name of the service.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of permissions.</returns>
    Task<IEnumerable<Permission>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves permissions by a list of their unique identifiers asynchronously.
    /// </summary>
    /// <param name="permissionIds">The list of permission identifiers.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of permissions.</returns>
    Task<IEnumerable<Permission>> GetByIdsAsync(IEnumerable<string> permissionIds, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new permission asynchronously.
    /// </summary>
    /// <param name="permission">The permission to create.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The created permission.</returns>
    Task<Permission> CreateAsync(Permission permission, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates multiple permissions asynchronously.
    /// </summary>
    /// <param name="permissions">The permissions to create.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task CreateManyAsync(IEnumerable<Permission> permissions, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates multiple permissions asynchronously.
    /// </summary>
    /// <param name="permissions">The permissions to update.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task UpdateManyAsync(IEnumerable<Permission> permissions, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a permission exists asynchronously.
    /// </summary>
    /// <param name="permissionId">The unique identifier of the permission.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if the permission exists; otherwise, false.</returns>
    Task<bool> ExistsAsync(string permissionId, CancellationToken cancellationToken = default);
}
