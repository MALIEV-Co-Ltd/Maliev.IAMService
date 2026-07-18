namespace Maliev.IAMService.Application.DTOs.Responses;

/// <summary>
/// Represents a response containing permission details.
/// </summary>
public record PermissionResponse
{
    /// <summary>
    /// Gets or sets the unique identifier of the permission.
    /// </summary>
    public required string PermissionId { get; init; }

    /// <summary>
    /// Gets or sets the name of the service associated with the permission.
    /// </summary>
    public required string ServiceName { get; init; }

    /// <summary>
    /// Gets or sets the resource type associated with the permission.
    /// </summary>
    public required string ResourceType { get; init; }

    /// <summary>
    /// Gets or sets the action associated with the permission.
    /// </summary>
    public required string Action { get; init; }

    /// <summary>
    /// Gets or sets the description of the permission.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Gets or sets the date and time when the permission was created.
    /// </summary>
    public required DateTime CreatedAt { get; init; }
}
