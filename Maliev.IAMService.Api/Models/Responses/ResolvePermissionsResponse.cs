namespace Maliev.IAMService.Api.Models.Responses;

/// <summary>
/// Represents a response containing resolved permissions for a principal.
/// </summary>
public record ResolvePermissionsResponse
{
    /// <summary>
    /// Gets or sets the unique identifier of the principal.
    /// </summary>
    public required Guid PrincipalId { get; init; }
    /// <summary>
    /// Gets or sets the list of permissions assigned to the principal.
    /// </summary>
    public required List<string> Permissions { get; init; }

    /// <summary>
    /// List of role IDs assigned to the principal (e.g., "roles.accounting.admin")
    /// </summary>
    public required List<string> Roles { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456")
    /// </summary>
    public string? ResourcePath { get; init; }

    /// <summary>
    /// When the cached permissions expire (for cache control)
    /// </summary>
    public DateTime? CacheUntil { get; init; }

    /// <summary>
    /// Gets or sets a value indicating whether the result was retrieved from cache.
    /// </summary>
    public required bool FromCache { get; init; }
}
