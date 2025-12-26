namespace Maliev.IAMService.Api.Models.Responses;

public record RoleResponse
{
    public required string RoleId { get; init; }
    public required string ServiceName { get; init; }
    public required string Description { get; init; }
    public required bool IsCustom { get; init; }
    public required List<string> PermissionIds { get; init; }
    public required DateTime CreatedAt { get; init; }
    public DateTime? UpdatedAt { get; init; }
}
