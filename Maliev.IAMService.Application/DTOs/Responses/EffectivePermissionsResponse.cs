namespace Maliev.IAMService.Application.DTOs.Responses;

/// <summary>
/// Response DTO for querying effective permissions.
/// </summary>
public record EffectivePermissionsResponse
{
    /// <summary>
    /// Gets or sets the unique identifier of the principal.
    /// </summary>
    public required Guid PrincipalId { get; init; }

    /// <summary>
    /// Gets or sets the collection of effective permissions.
    /// </summary>
    public required IEnumerable<EffectivePermissionDto> Permissions { get; init; }

    /// <summary>
    /// Gets or sets the date and time when the query was performed.
    /// </summary>
    public required DateTime QueriedAt { get; init; }
}

/// <summary>
/// Represents an effective permission data transfer object.
/// </summary>
public record EffectivePermissionDto
{
    /// <summary>
    /// Gets or sets the unique identifier of the permission.
    /// </summary>
    public required string PermissionId { get; init; }

    /// <summary>
    /// Gets or sets the description of the permission.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Gets or sets the collection of roles that grant this permission.
    /// </summary>
    public required IEnumerable<string> GrantedByRoles { get; init; }

    /// <summary>
    /// Gets or sets the resource path if the permission is scoped.
    /// </summary>
    public string? ResourcePath { get; init; }

    /// <summary>
    /// Gets or sets a value indicating whether the permission is resource-scoped.
    /// </summary>
    public bool IsScoped { get; init; }
}
