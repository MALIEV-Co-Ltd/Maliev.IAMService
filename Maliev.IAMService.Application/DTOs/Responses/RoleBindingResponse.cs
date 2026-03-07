namespace Maliev.IAMService.Application.DTOs.Responses;

/// <summary>
/// Represents a response containing role binding details.
/// </summary>
public record RoleBindingResponse
{
    /// <summary>
    /// Gets or sets the unique identifier of the binding.
    /// </summary>
    public required Guid BindingId { get; init; }

    /// <summary>
    /// Gets or sets the unique identifier of the principal.
    /// </summary>
    public required Guid PrincipalId { get; init; }

    /// <summary>
    /// Gets or sets the unique identifier of the role.
    /// </summary>
    public required string RoleId { get; init; }

    /// <summary>
    /// Gets or sets the hierarchical resource path (e.g., "projects/123/datasets/456").
    /// NULL for global role bindings.
    /// </summary>
    public string? ResourcePath { get; init; }

    /// <summary>
    /// Gets or sets the date and time when the role was granted.
    /// </summary>
    public required DateTime GrantedAt { get; init; }

    /// <summary>
    /// Gets or sets the expiration date and time of the role binding.
    /// </summary>
    public DateTime? ExpiresAt { get; init; }
}
