namespace Maliev.IAMService.Api.Models.Requests;

public record RegisterPermissionsRequest
{
    public required string ServiceName { get; init; }
    public required List<PermissionDto> Permissions { get; init; }
}

public record PermissionDto
{
    public required string PermissionId { get; init; }
    public required string Description { get; init; }
}
