namespace Maliev.IAMService.Api.Models.Requests;

public record RegisterRolesRequest
{
    public required string ServiceName { get; init; }
    public required List<RoleDto> Roles { get; init; }
}

public record RoleDto
{
    public required string RoleId { get; init; }
    public required string Description { get; init; }
    public required List<string> PermissionIds { get; init; }
    public bool IsCustom { get; init; } = false;
}
