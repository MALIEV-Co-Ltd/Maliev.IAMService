namespace Maliev.IAMService.Api.Models.Responses;

/// <summary>
/// Represents a response containing an audit log entry.
/// </summary>
public record AuditLogEntryResponse
{
    /// <summary>
    /// Gets or sets the unique identifier of the log entry.
    /// </summary>
    public required Guid LogId { get; init; }
    /// <summary>
    /// Gets or sets the action performed.
    /// </summary>
    public required string Action { get; init; }
    /// <summary>
    /// Gets or sets the unique identifier of the principal affected.
    /// </summary>
    public Guid? PrincipalId { get; init; }
    /// <summary>
    /// Gets or sets the unique identifier of the role affected.
    /// </summary>
    public string? RoleId { get; init; }
    /// <summary>
    /// Gets or sets the unique identifier of the permission affected.
    /// </summary>
    public string? PermissionId { get; init; }
    /// <summary>
    /// Gets or sets the unique identifier of the user who performed the action.
    /// </summary>
    public required Guid PerformedBy { get; init; }
    /// <summary>
    /// Gets or sets the date and time when the action was performed.
    /// </summary>
    public required DateTime Timestamp { get; init; }
    /// <summary>
    /// Gets or sets the IP address where the request originated.
    /// </summary>
    public string? IpAddress { get; init; }
    /// <summary>
    /// Gets or sets the user agent string of the client.
    /// </summary>
    public string? UserAgent { get; init; }
    /// <summary>
    /// Gets or sets additional details about the action.
    /// </summary>
    public string? Details { get; init; }
}
