namespace Maliev.IAMService.Application.DTOs.Requests;

/// <summary>
/// Represents a request to register permissions for a service.
/// </summary>
public record RegisterPermissionsRequest
{
    /// <summary>Gets or sets the name of the service registering permissions.</summary>
    public required string ServiceName { get; init; }
    /// <summary>Gets or sets the list of permissions to register.</summary>
    public required List<PermissionDto> Permissions { get; init; }
}

/// <summary>Represents a permission data transfer object.</summary>
public record PermissionDto
{
    /// <summary>Gets or sets the unique identifier of the permission.</summary>
    public required string PermissionId { get; init; }
    /// <summary>Gets or sets the description of the permission.</summary>
    public required string Description { get; init; }
}
