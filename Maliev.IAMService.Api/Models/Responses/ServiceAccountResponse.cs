namespace Maliev.IAMService.Api.Models.Responses;

public record ServiceAccountResponse
{
    public required Guid PrincipalId { get; init; }
    public required string Name { get; init; }
    public string? Description { get; init; }
    public string? ApiKey { get; init; } // Only returned on creation
    public string? ApiKeyPrefix { get; init; }
    public required DateTime CreatedAt { get; init; }
}
