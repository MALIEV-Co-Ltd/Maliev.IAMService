namespace Maliev.IAMService.Api.Models.Requests;

/// <summary>
/// Represents a request to query audit logs.
/// </summary>
public record AuditLogQueryRequest
{
    /// <summary>
    /// Gets or sets the start date and time for the query.
    /// </summary>
    public DateTime? FromDate { get; init; }
    /// <summary>
    /// Gets or sets the end date and time for the query.
    /// </summary>
    public DateTime? ToDate { get; init; }
    /// <summary>
    /// Gets or sets the unique identifier of the principal to filter by.
    /// </summary>
    public Guid? PrincipalId { get; init; }
    /// <summary>
    /// Gets or sets the action to filter by.
    /// </summary>
    public string? Action { get; init; }
    /// <summary>
    /// Gets or sets the number of records to skip.
    /// </summary>
    public int Skip { get; init; } = 0;
    /// <summary>
    /// Gets or sets the number of records to take.
    /// </summary>
    public int Take { get; init; } = 50;
}
