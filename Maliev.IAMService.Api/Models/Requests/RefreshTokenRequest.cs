namespace Maliev.IAMService.Api.Models.Requests;

// T136: Request DTO for refreshing JWT tokens
public record RefreshTokenRequest
{
    public required string RefreshToken { get; init; }
}
