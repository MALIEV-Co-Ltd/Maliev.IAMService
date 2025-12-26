namespace Maliev.IAMService.Api.Models.Requests;

public record CreateCustomRoleRequest
{
    public required string RoleId { get; init; }
    public required string ServiceName { get; init; }
    public required string Description { get; init; }
    public required List<string> PermissionIds { get; init; }
}
