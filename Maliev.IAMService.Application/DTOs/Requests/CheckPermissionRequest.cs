namespace Maliev.IAMService.Application.DTOs.Requests;

/// <summary>Represents a request to check if a principal has a specific permission.</summary>
public record CheckPermissionRequest
{
    /// <summary>Gets or sets the identifier of the principal (can be a GUID, email, or service name).</summary>
    public required string PrincipalId { get; init; }
    /// <summary>Gets or sets the unique identifier of the permission.</summary>
    public required string PermissionId { get; init; }
    /// <summary>Gets or sets hierarchical resource path.</summary>
    public string? ResourcePath { get; init; }
}
