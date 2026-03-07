namespace Maliev.IAMService.Application.DTOs.Responses;

/// <summary>
/// Response model for principal creation.
/// </summary>
public record CreatePrincipalResponse
{
    /// <summary>
    /// Gets or sets the unique principal identifier.
    /// </summary>
    public Guid PrincipalId { get; init; }

    /// <summary>
    /// Gets or sets the timestamp when the principal was created.
    /// </summary>
    public DateTime CreatedAt { get; init; }
}
