namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Request DTO for refreshing JWT tokens.
/// </summary>
public record RefreshTokenRequest
{
    /// <summary>
    /// Gets or sets the refresh token string.
    /// </summary>
    public required string RefreshToken { get; init; }
}
