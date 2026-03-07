namespace Maliev.IAMService.Application.DTOs.Requests;

/// <summary>Request DTO for issuing JWT tokens.</summary>
public record IssueTokenRequest
{
    /// <summary>Gets or sets the identifier of the principal (GUID, email, or service name).</summary>
    public required string PrincipalId { get; init; }
    /// <summary>Gets or sets the hierarchical resource path.</summary>
    public string? ResourcePath { get; init; }
    /// <summary>Gets or sets the token expiration time in minutes. Default to 60 if not specified.</summary>
    public int? ExpiresInMinutes { get; init; }
}
