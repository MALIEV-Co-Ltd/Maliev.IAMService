namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Represents a request to revoke a role assignment.
/// </summary>
public record RevokeRoleRequest
{
    /// <summary>
    /// Gets or sets the unique identifier of the role binding to revoke.
    /// </summary>
    public required Guid BindingId { get; init; }
}
