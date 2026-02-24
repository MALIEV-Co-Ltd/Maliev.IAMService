using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

/// <summary>
/// Interface for repository operations related to roles.
/// </summary>
public interface IRoleRepository
{
    /// <summary>
    /// Retrieves a role by its unique identifier asynchronously.
    /// </summary>
    /// <param name="roleId">The unique identifier of the role.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The role if found; otherwise, null.</returns>
    Task<Role?> GetByIdAsync(string roleId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all roles asynchronously.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of all roles.</returns>
    Task<IEnumerable<Role>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves roles associated with a specific service asynchronously.
    /// </summary>
    /// <param name="serviceName">The name of the service.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of roles.</returns>
    Task<IEnumerable<Role>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all custom roles asynchronously.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of custom roles.</returns>
    Task<IEnumerable<Role>> GetCustomRolesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves roles by a list of their unique identifiers asynchronously.
    /// </summary>
    /// <param name="roleIds">The list of role identifiers.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of roles.</returns>
    Task<IEnumerable<Role>> GetByIdsAsync(IEnumerable<string> roleIds, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves permissions associated with multiple roles asynchronously.
    /// </summary>
    /// <param name="roleIds">The list of role identifiers.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of role-permission mappings.</returns>
    Task<IEnumerable<RolePermission>> GetPermissionsForRolesAsync(IEnumerable<string> roleIds, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new role asynchronously.
    /// </summary>
    /// <param name="role">The role to create.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The created role.</returns>
    Task<Role> CreateAsync(Role role, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates multiple roles in a single database transaction.
    /// </summary>
    /// <param name="roles">The roles to create.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task CreateManyAsync(IEnumerable<Role> roles, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing role asynchronously.
    /// </summary>
    /// <param name="role">The role to update.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task UpdateAsync(Role role, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a role by its unique identifier asynchronously.
    /// </summary>
    /// <param name="roleId">The unique identifier of the role.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task DeleteAsync(string roleId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a role has active bindings asynchronously.
    /// </summary>
    /// <param name="roleId">The unique identifier of the role.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if the role has active bindings; otherwise, false.</returns>
    Task<bool> HasActiveBindingsAsync(string roleId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves permissions associated with a role asynchronously.
    /// </summary>
    /// <param name="roleId">The unique identifier of the role.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of permissions.</returns>
    Task<IEnumerable<Permission>> GetRolePermissionsAsync(string roleId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a role is already being tracked by the database context.
    /// </summary>
    /// <param name="roleId">The unique identifier of the role.</param>
    /// <returns>The tracked role if found; otherwise, null.</returns>
    Role? GetTracked(string roleId);

    /// <summary>
    /// Adds a permission to a role idempotently.
    /// </summary>
    /// <param name="roleId">The unique identifier of the role.</param>
    /// <param name="permissionId">The unique identifier of the permission.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if the permission was added; false if it already exists on the role.</returns>
    Task<bool> AddPermissionToRoleAsync(string roleId, string permissionId, CancellationToken cancellationToken = default);
}
