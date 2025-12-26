namespace Maliev.IAMService.Api.Models.Responses;

public record CheckPermissionResponse
{
    public required Guid PrincipalId { get; init; }
    public required string PermissionId { get; init; }
    public required bool Allowed { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456")
    /// </summary>
    public string? ResourcePath { get; init; }

    public required bool FromCache { get; init; }
    public required long LatencyMs { get; init; }
}
