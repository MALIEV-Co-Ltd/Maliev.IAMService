namespace Maliev.IAMService.Application.DTOs.Responses;

/// <summary>
/// Represents a response containing role details.
/// </summary>
public record RoleResponse
{
    /// <summary>
    /// Gets or sets the unique identifier of the role.
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
    /// Gets or sets a value indicating whether the role is custom.
    /// </summary>
    public required bool IsCustom { get; init; }

    /// <summary>
    /// Gets or sets the list of permission identifiers associated with the role.
    /// </summary>
    public required List<string> PermissionIds { get; init; }

    /// <summary>
    /// Gets or sets the date and time when the role was created.
    /// </summary>
    public required DateTime CreatedAt { get; init; }

    /// <summary>
    /// Gets or sets the date and time when the role was last updated.
    /// </summary>
    public DateTime? UpdatedAt { get; init; }
}
