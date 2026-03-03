using Asp.Versioning;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.IAMService.Domain.Constants;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Domain.Entities;
using Microsoft.AspNetCore.Mvc;

namespace Maliev.IAMService.Api.Controllers;

/// <summary>
/// Controller for retrieving and querying IAM audit logs.
/// Provides comprehensive audit trail access for security monitoring and compliance requirements.
/// Supports filtering by date range, principal, and action type with pagination support.
/// </summary>
[ApiController]
[ApiVersion("1.0")]
[Route("iam/v{version:apiVersion}/audit")]
public class AuditController : ControllerBase
{
    private readonly IAuditRepository _auditRepository;
    private readonly ILogger<AuditController> _logger;

    /// <summary>
    /// Initializes a new instance of the AuditController class.
    /// </summary>
    /// <param name="auditRepository">Repository for accessing audit log data and history.</param>
    /// <param name="logger">Logger instance for recording diagnostic information.</param>
    public AuditController(IAuditRepository auditRepository, ILogger<AuditController> logger)
    {
        _auditRepository = auditRepository;
        _logger = logger;
    }

    /// <summary>
    /// Retrieves audit logs with support for multiple filtering criteria and pagination.
    /// Queries audit records based on the specified filter parameters with the following priority:
    /// 1. Date range filtering (FromDate and ToDate) - returns logs within the specified date range
    /// 2. Principal ID filtering (PrincipalId) - returns logs for a specific principal
    /// 3. Action type filtering (Action) - returns logs for a specific action type
    /// 4. If no filters are provided, returns all logs with pagination
    ///
    /// Supports pagination via Skip and Take parameters to handle large result sets.
    /// All filters are applied in sequence and only the first matching filter category is used.
    /// Timestamps are stored as UTC and represent when the action occurred.
    /// </summary>
    /// <param name="request">Query request containing filter criteria (date range, principal ID, action type) and pagination parameters (Skip, Take).</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>Paginated list of audit log entries matching the specified criteria.
    /// Each log entry includes LogId, Action, PrincipalId, RoleId, PermissionId, PerformedBy, Timestamp (UTC), IpAddress, UserAgent, and Details.
    /// Returns 200 OK with the filtered audit logs.</returns>
    [HttpGet("logs")]
    [RequirePermission(IAMPermissions.AuditList)]
    public async Task<IActionResult> GetAuditLogs([FromQuery] AuditLogQueryRequest request, CancellationToken cancellationToken)
    {
        IEnumerable<IAMAuditLog> logs;

        // T101: Date range filtering
        if (request.FromDate.HasValue && request.ToDate.HasValue)
        {
            logs = await _auditRepository.GetByDateRangeAsync(request.FromDate.Value, request.ToDate.Value, cancellationToken);
        }
        // T102: Principal ID filtering
        else if (request.PrincipalId.HasValue)
        {
            logs = await _auditRepository.GetByPrincipalAsync(request.PrincipalId.Value, cancellationToken);
        }
        // T103: Action type filtering
        else if (!string.IsNullOrWhiteSpace(request.Action))
        {
            logs = await _auditRepository.GetByActionAsync(request.Action, cancellationToken);
        }
        else
        {
            logs = await _auditRepository.GetAllAsync(request.Skip, request.Take, cancellationToken);
        }

        // T104: Pagination support
        var pagedLogs = logs.Skip(request.Skip).Take(request.Take);

        var response = pagedLogs.Select(log => new AuditLogEntryResponse
        {
            LogId = log.LogId,
            Action = log.Action,
            PrincipalId = log.PrincipalId,
            RoleId = log.RoleId,
            PermissionId = log.PermissionId,
            PerformedBy = log.PerformedBy,
            Timestamp = log.Timestamp,
            IpAddress = log.IpAddress?.ToString(),
            UserAgent = log.UserAgent,
            Details = log.Details
        });

        return Ok(response);
    }
}
