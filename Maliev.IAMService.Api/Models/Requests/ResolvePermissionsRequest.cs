namespace Maliev.IAMService.Api.Models.Requests;

public record ResolvePermissionsRequest
{
    public required Guid PrincipalId { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456")
    /// </summary>
    public string? ResourcePath { get; init; }

    /// <summary>
    /// Request timestamp (for condition evaluation)
    /// </summary>
    public DateTime? RequestTime { get; init; }

    /// <summary>
    /// Request IP address (for condition evaluation)
    /// </summary>
    public string? RequestIp { get; init; }
}
