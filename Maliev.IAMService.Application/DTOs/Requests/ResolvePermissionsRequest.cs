namespace Maliev.IAMService.Application.DTOs.Requests;

/// <summary>Represents a request to resolve permissions for a principal.</summary>
public record ResolvePermissionsRequest
{
    /// <summary>Gets or sets the identifier of the principal (can be a GUID, email, or service name).</summary>
    public required string PrincipalId { get; init; }
    /// <summary>Gets or sets hierarchical resource path.</summary>
    public string? ResourcePath { get; init; }
    /// <summary>Gets or sets request timestamp (for condition evaluation).</summary>
    public DateTime? RequestTime { get; init; }
    /// <summary>Gets or sets request IP address (for condition evaluation).</summary>
    public string? RequestIp { get; init; }
}
