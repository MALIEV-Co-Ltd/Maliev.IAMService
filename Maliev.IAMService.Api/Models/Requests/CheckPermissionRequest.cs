namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Represents a request to check if a principal has a specific permission.
/// </summary>
public record CheckPermissionRequest
{
    /// <summary>
    /// Gets or sets the unique identifier of the principal.
    /// </summary>
    public required Guid PrincipalId { get; init; }
    /// <summary>
    /// Gets or sets the unique identifier of the permission.
    /// </summary>
    public required string PermissionId { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456")
    /// </summary>
    public string? ResourcePath { get; init; }
}
