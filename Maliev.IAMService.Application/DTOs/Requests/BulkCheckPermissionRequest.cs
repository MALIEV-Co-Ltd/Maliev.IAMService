namespace Maliev.IAMService.Application.DTOs.Requests;

/// <summary>Request for checking multiple permissions in a single call.</summary>
public record BulkCheckPermissionRequest
{
    /// <summary>The principal identifier to check permissions for (GUID, email, or service name).</summary>
    public required string PrincipalId { get; init; }
    /// <summary>List of permission checks to perform.</summary>
    public required List<PermissionCheckItem> PermissionChecks { get; init; }
}

/// <summary>Individual permission check item for bulk requests.</summary>
public record PermissionCheckItem
{
    /// <summary>The permission ID to check.</summary>
    public required string PermissionId { get; init; }
    /// <summary>Optional hierarchical resource path for scoped checking.</summary>
    public string? ResourcePath { get; init; }
}
