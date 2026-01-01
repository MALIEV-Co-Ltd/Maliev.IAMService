namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Request DTO for issuing JWT tokens.
/// </summary>
public record IssueTokenRequest
{
    /// <summary>
    /// Gets or sets the unique identifier of the principal.
    /// </summary>
    public required Guid PrincipalId { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456")
    /// </summary>
    public string? ResourcePath { get; init; }

    /// <summary>
    /// Gets or sets the token expiration time in minutes. Default to 60 if not specified.
    /// </summary>
    public int? ExpiresInMinutes { get; init; } // Default to 60 if not specified
}
