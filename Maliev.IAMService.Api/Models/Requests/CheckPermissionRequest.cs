namespace Maliev.IAMService.Api.Models.Requests;

public record CheckPermissionRequest
{
    public required Guid PrincipalId { get; init; }
    public required string PermissionId { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456")
    /// </summary>
    public string? ResourcePath { get; init; }
}
