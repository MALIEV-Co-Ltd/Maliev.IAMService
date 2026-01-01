namespace Maliev.IAMService.Api.Models.Responses;

/// <summary>
/// Represents a response after rotating an API key.
/// </summary>
public record RotateApiKeyResponse
{
    /// <summary>
    /// Gets or sets the unique identifier of the principal.
    /// </summary>
    public required Guid PrincipalId { get; init; }
    /// <summary>
    /// Gets or sets the new API key string.
    /// </summary>
    public required string NewApiKey { get; init; }
    /// <summary>
    /// Gets or sets the prefix of the API key.
    /// </summary>
    public required string ApiKeyPrefix { get; init; }
    /// <summary>
    /// Gets or sets the date and time when the API key was created.
    /// </summary>
    public required DateTime CreatedAt { get; init; }
}
