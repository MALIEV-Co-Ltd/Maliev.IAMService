namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Represents a request to resolve permissions for a principal.
/// </summary>
public record ResolvePermissionsRequest
{
    /// <summary>
    /// Gets or sets the identifier of the principal (can be a GUID, email, or service name).
    /// </summary>
    public required string PrincipalId { get; init; }

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
