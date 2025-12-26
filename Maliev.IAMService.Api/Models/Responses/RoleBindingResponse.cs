namespace Maliev.IAMService.Api.Models.Responses;

public record RoleBindingResponse
{
    public required Guid BindingId { get; init; }
    public required Guid PrincipalId { get; init; }
    public required string RoleId { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456").
    /// NULL for global role bindings.
    /// </summary>
    public string? ResourcePath { get; init; }

    public required DateTime GrantedAt { get; init; }
    public DateTime? ExpiresAt { get; init; }
}
