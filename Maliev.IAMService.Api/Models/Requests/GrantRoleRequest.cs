namespace Maliev.IAMService.Api.Models.Requests;

public record GrantRoleRequest
{
    public required string RoleId { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456").
    /// Supports wildcards: /* (single-level) and /** (multi-level).
    /// NULL for global role bindings.
    /// </summary>
    public string? ResourcePath { get; init; }

    public DateTime? ExpiresAt { get; init; }
}
