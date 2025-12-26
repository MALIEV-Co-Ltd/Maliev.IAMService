namespace Maliev.IAMService.Api.Models.Responses;

public record PermissionResponse
{
    public required string PermissionId { get; init; }
    public required string ServiceName { get; init; }
    public required string ResourceType { get; init; }
    public required string Action { get; init; }
    public required string Description { get; init; }
    public required DateTime CreatedAt { get; init; }
}
