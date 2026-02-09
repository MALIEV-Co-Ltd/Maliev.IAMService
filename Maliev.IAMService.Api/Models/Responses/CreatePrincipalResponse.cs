namespace Maliev.IAMService.Api.Models.Responses;

/// <summary>
/// Response model for principal creation.
/// </summary>
public record CreatePrincipalResponse
{
    /// <summary>
    /// Unique principal identifier.
    /// </summary>
    public Guid PrincipalId { get; init; }

    /// <summary>
    /// Timestamp when the principal was created.
    /// </summary>
    public DateTime CreatedAt { get; init; }
}
