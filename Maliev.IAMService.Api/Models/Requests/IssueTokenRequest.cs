namespace Maliev.IAMService.Api.Models.Requests;

// T134: Request DTO for issuing JWT tokens
public record IssueTokenRequest
{
    public required Guid PrincipalId { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456")
    /// </summary>
    public string? ResourcePath { get; init; }

    public int? ExpiresInMinutes { get; init; } // Default to 60 if not specified
}
