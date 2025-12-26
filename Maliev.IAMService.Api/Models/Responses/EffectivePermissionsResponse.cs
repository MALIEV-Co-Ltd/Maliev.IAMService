namespace Maliev.IAMService.Api.Models.Responses;

// T149: Response DTO for querying effective permissions
public record EffectivePermissionsResponse
{
    public required Guid PrincipalId { get; init; }
    public required IEnumerable<EffectivePermissionDto> Permissions { get; init; }
    public required DateTime QueriedAt { get; init; }
}

public record EffectivePermissionDto
{
    public required string PermissionId { get; init; }
    public required string Description { get; init; }
    public required IEnumerable<string> GrantedByRoles { get; init; }
    public string? ResourcePath { get; init; }
    public bool IsScoped { get; init; } // T152: Indicates if permission is resource-scoped
}
