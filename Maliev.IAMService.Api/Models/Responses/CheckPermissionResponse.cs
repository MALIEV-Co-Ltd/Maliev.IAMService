namespace Maliev.IAMService.Api.Models.Responses;

/// <summary>
/// Represents the result of a permission check.
/// </summary>
public record CheckPermissionResponse
{
    /// <summary>
    /// Gets or sets the unique identifier of the principal.
    /// </summary>
    public required Guid PrincipalId { get; init; }
    /// <summary>
    /// Gets or sets the unique identifier of the permission checked.
    /// </summary>
    public required string PermissionId { get; init; }
    /// <summary>
    /// Gets or sets a value indicating whether the permission is allowed.
    /// </summary>
    public required bool Allowed { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456")
    /// </summary>
    public string? ResourcePath { get; init; }

    /// <summary>
    /// Gets or sets a value indicating whether the result was retrieved from cache.
    /// </summary>
    public required bool FromCache { get; init; }
    /// <summary>
    /// Gets or sets the latency in milliseconds.
    /// </summary>
    public required long LatencyMs { get; init; }
}
