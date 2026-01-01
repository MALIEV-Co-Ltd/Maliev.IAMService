namespace Maliev.IAMService.Api.Models.Responses;

/// <summary>
/// Represents a response containing service account details.
/// </summary>
public record ServiceAccountResponse
{
    /// <summary>
    /// Gets or sets the unique identifier of the principal (service account).
    /// </summary>
    public required Guid PrincipalId { get; init; }
    /// <summary>
    /// Gets or sets the name of the service account.
    /// </summary>
    public required string Name { get; init; }
    /// <summary>
    /// Gets or sets the description of the service account.
    /// </summary>
    public string? Description { get; init; }
    /// <summary>
    /// Gets or sets the API key string (only returned on creation).
    /// </summary>
    public string? ApiKey { get; init; } // Only returned on creation
    /// <summary>
    /// Gets or sets the prefix of the API key.
    /// </summary>
    public string? ApiKeyPrefix { get; init; }
    /// <summary>
    /// Gets or sets the date and time when the service account was created.
    /// </summary>
    public required DateTime CreatedAt { get; init; }
}
