namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Represents a request to register roles for a service.
/// </summary>
public record RegisterRolesRequest
{
    /// <summary>
    /// Gets or sets the name of the service registering roles.
    /// </summary>
    public required string ServiceName { get; init; }
    /// <summary>
    /// Gets or sets the list of roles to register.
    /// </summary>
    public required List<RoleDto> Roles { get; init; }
}

/// <summary>
/// Represents a role data transfer object.
/// </summary>
public record RoleDto
{
    /// <summary>
    /// Gets or sets the unique identifier of the role.
    /// </summary>
    public required string RoleId { get; init; }
    /// <summary>
    /// Gets or sets the description of the role.
    /// </summary>
    public required string Description { get; init; }
    /// <summary>
    /// Gets or sets the list of permission identifiers associated with the role.
    /// </summary>
    public required List<string> PermissionIds { get; init; }
    /// <summary>
    /// Gets or sets a value indicating whether the role is custom.
    /// </summary>
    public bool IsCustom { get; init; } = false;
}
