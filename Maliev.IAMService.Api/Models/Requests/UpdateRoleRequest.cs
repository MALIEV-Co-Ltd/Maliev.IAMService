namespace Maliev.IAMService.Api.Models.Requests;

public record UpdateRoleRequest
{
    public string? Description { get; init; }
    public List<string>? AddPermissionIds { get; init; }
    public List<string>? RemovePermissionIds { get; init; }
}
