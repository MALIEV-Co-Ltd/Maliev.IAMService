using System.Text.Json.Serialization;

namespace Maliev.IAMService.Api.Models.Responses;

/// <summary>
/// Response DTO for JWT token issuance.
/// </summary>
public record TokenResponse
{
    /// <summary>
    /// Gets or sets the access token string.
    /// </summary>
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; init; }

    /// <summary>
    /// Gets or sets the token type (e.g., "Bearer").
    /// </summary>
    [JsonPropertyName("token_type")]
    public required string TokenType { get; init; } = "Bearer";

    /// <summary>
    /// Gets or sets the expiration time in seconds.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; init; } // Seconds until expiration

    /// <summary>
    /// Gets or sets the refresh token string.
    /// </summary>
    [JsonPropertyName("refresh_token")]
    public required string RefreshToken { get; init; }

    /// <summary>
    /// Gets or sets the date and time when the token was issued.
    /// </summary>
    [JsonPropertyName("issued_at")]
    public required DateTime IssuedAt { get; init; }

    /// <summary>
    /// Gets or sets the date and time when the token expires.
    /// </summary>
    [JsonPropertyName("expires_at")]
    public required DateTime ExpiresAt { get; init; }
}
