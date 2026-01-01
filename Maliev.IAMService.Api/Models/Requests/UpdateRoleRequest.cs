namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Represents a request to update an existing role.
/// </summary>
public record UpdateRoleRequest
{
    /// <summary>
    /// Gets or sets the new description of the role.
    /// </summary>
    public string? Description { get; init; }
    /// <summary>
    /// Gets or sets the list of permission identifiers to add to the role.
    /// </summary>
    public List<string>? AddPermissionIds { get; init; }
    /// <summary>
    /// Gets or sets the list of permission identifiers to remove from the role.
    /// </summary>
    public List<string>? RemovePermissionIds { get; init; }
}
