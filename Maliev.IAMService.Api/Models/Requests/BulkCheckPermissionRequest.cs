namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Request for checking multiple permissions in a single call.
/// </summary>
public record BulkCheckPermissionRequest
{
    /// <summary>
    /// The principal ID to check permissions for.
    /// </summary>
    public required Guid PrincipalId { get; init; }

    /// <summary>
    /// List of permission checks to perform.
    /// </summary>
    public required List<PermissionCheckItem> PermissionChecks { get; init; }
}

/// <summary>
/// Individual permission check item for bulk requests.
/// </summary>
public record PermissionCheckItem
{
    /// <summary>
    /// The permission ID to check.
    /// </summary>
    public required string PermissionId { get; init; }

    /// <summary>
    /// Optional hierarchical resource path for scoped checking.
    /// </summary>
    public string? ResourcePath { get; init; }
}
