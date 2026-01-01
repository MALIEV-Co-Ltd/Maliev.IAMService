namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Represents a request to create a new service account.
/// </summary>
public record CreateServiceAccountRequest
{
    /// <summary>
    /// Gets or sets the name of the service account.
    /// </summary>
    public required string Name { get; init; }
    /// <summary>
    /// Gets or sets the description of the service account.
    /// </summary>
    public string? Description { get; init; }
}
