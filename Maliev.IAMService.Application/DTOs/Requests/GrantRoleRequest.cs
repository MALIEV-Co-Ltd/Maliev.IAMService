namespace Maliev.IAMService.Application.DTOs.Requests;

/// <summary>Represents a request to grant a role to a principal.</summary>
public record GrantRoleRequest
{
    /// <summary>Gets or sets the unique identifier of the role.</summary>
    public required string RoleId { get; init; }
    /// <summary>Gets or sets hierarchical resource path. NULL for global role bindings.</summary>
    public string? ResourcePath { get; init; }
    /// <summary>Gets or sets the expiration date and time for the role grant.</summary>
    public DateTime? ExpiresAt { get; init; }
}
