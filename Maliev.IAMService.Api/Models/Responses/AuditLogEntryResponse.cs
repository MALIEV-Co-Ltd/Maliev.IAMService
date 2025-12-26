using System.Net;

namespace Maliev.IAMService.Api.Models.Responses;

public record AuditLogEntryResponse
{
    public required Guid LogId { get; init; }
    public required string Action { get; init; }
    public Guid? PrincipalId { get; init; }
    public string? RoleId { get; init; }
    public string? PermissionId { get; init; }
    public required Guid PerformedBy { get; init; }
    public required DateTime Timestamp { get; init; }
    public string? IpAddress { get; init; }
    public string? UserAgent { get; init; }
    public string? Details { get; init; }
}
