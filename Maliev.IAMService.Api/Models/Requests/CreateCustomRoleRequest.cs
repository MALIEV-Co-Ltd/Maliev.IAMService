namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Represents a request to create a new custom role.
/// </summary>
public record CreateCustomRoleRequest
{
    /// <summary>
    /// Gets or sets the unique identifier for the custom role.
    /// </summary>
    public required string RoleId { get; init; }
    /// <summary>
    /// Gets or sets the name of the service associated with the role.
    /// </summary>
    public required string ServiceName { get; init; }
    /// <summary>
    /// Gets or sets the description of the role.
    /// </summary>
    public required string Description { get; init; }
    /// <summary>
    /// Gets or sets the list of permission identifiers associated with the role.
    /// </summary>
    public required List<string> PermissionIds { get; init; }
}
