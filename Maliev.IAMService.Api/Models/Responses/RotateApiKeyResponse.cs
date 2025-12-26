namespace Maliev.IAMService.Api.Models.Responses;

public record RotateApiKeyResponse
{
    public required Guid PrincipalId { get; init; }
    public required string NewApiKey { get; init; }
    public required string ApiKeyPrefix { get; init; }
    public required DateTime CreatedAt { get; init; }
}
