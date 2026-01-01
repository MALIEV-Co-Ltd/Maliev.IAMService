namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Represents a request to create a new user principal.
/// </summary>
public record CreateUserPrincipalRequest
{
    /// <summary>
    /// Gets or sets the email address of the user.
    /// </summary>
    public string? Email { get; init; }
    /// <summary>
    /// Gets or sets the name of the linked service (e.g., "Google", "Facebook").
    /// </summary>
    public string? LinkedService { get; init; }
    /// <summary>
    /// Gets or sets the unique identifier of the user in the linked service.
    /// </summary>
    public Guid? LinkedEntityId { get; init; }
}
