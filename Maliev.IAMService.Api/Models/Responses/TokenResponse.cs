namespace Maliev.IAMService.Api.Models.Responses;

// T135: Response DTO for JWT token issuance
public record TokenResponse
{
    public required string AccessToken { get; init; }
    public required string TokenType { get; init; } = "Bearer";
    public required int ExpiresIn { get; init; } // Seconds until expiration
    public required string RefreshToken { get; init; }
    public required DateTime IssuedAt { get; init; }
    public required DateTime ExpiresAt { get; init; }
}
