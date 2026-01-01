namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Represents a request to grant a role to a principal.
/// </summary>
public record GrantRoleRequest
{
    /// <summary>
    /// Gets or sets the unique identifier of the role.
    /// </summary>
    public required string RoleId { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456").
    /// Supports wildcards: /* (single-level) and /** (multi-level).
    /// NULL for global role bindings.
    /// </summary>
    public string? ResourcePath { get; init; }

    /// <summary>
    /// Gets or sets the expiration date and time for the role grant.
    /// </summary>
    public DateTime? ExpiresAt { get; init; }
}
