namespace Maliev.IAMService.Api.Models.Responses;

public record ResolvePermissionsResponse
{
    public required Guid PrincipalId { get; init; }
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

    public required bool FromCache { get; init; }
}
