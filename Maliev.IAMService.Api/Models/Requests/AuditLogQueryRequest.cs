namespace Maliev.IAMService.Api.Models.Requests;

public record AuditLogQueryRequest
{
    public DateTime? FromDate { get; init; }
    public DateTime? ToDate { get; init; }
    public Guid? PrincipalId { get; init; }
    public string? Action { get; init; }
    public int Skip { get; init; } = 0;
    public int Take { get; init; } = 50;
}
