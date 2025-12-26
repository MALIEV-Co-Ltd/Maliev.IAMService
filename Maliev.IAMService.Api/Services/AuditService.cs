using Maliev.IAMService.Data.Entities;
using Maliev.IAMService.Data.Repositories;

namespace Maliev.IAMService.Api.Services;

/// <summary>
/// Service for writing audit logs for IAM operations.
/// Records all security-relevant actions (role grants/revokes, token issuance, etc.) to persistent storage.
/// Logs include action type, principal ID, timestamp, and optional metadata.
/// Failures to write audit logs are logged but do not fail the operation.
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Writes an audit log entry with optional string details.
    /// Failures are logged but do not throw exceptions to avoid disrupting operations.
    /// </summary>
    /// <param name="action">The action being performed (e.g., "GRANT_ROLE", "ISSUE_TOKEN", "CREATE_SERVICE_ACCOUNT").</param>
    /// <param name="principalId">The principal ID performing or being affected by the action.</param>
    /// <param name="details">Optional string details about the action.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task LogAsync(string action, Guid principalId, string? details = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes an audit log entry with structured metadata.
    /// Metadata is serialized to JSON. Failures are logged but do not throw exceptions.
    /// </summary>
    /// <param name="action">The action being performed (e.g., "GRANT_ROLE", "ISSUE_TOKEN", "CREATE_SERVICE_ACCOUNT").</param>
    /// <param name="principalId">The principal ID performing or being affected by the action.</param>
    /// <param name="metadata">Optional dictionary of metadata (will be serialized to JSON).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task LogAsync(string action, Guid principalId, Dictionary<string, object>? metadata = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Implementation of audit service with fail-safe logging.
/// Writes audit logs to persistent storage via IAuditRepository.
/// Exceptions during logging are caught and logged to prevent operation failures.
/// </summary>
public class AuditService : IAuditService
{
    private readonly IAuditRepository _auditRepository;
    private readonly ILogger<AuditService> _logger;

    public AuditService(IAuditRepository auditRepository, ILogger<AuditService> logger)
    {
        _auditRepository = auditRepository;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task LogAsync(string action, Guid principalId, string? details = null, CancellationToken cancellationToken = default)
    {
        try
        {
            // Use a sentinel GUID for system actions instead of Guid.Empty to avoid constraint violations
            var performedBy = principalId == Guid.Empty
                ? new Guid("00000000-0000-0000-0000-000000000001") // System user sentinel
                : principalId;

            var auditLog = new IAMAuditLog
            {
                LogId = Guid.NewGuid(),
                Action = action,
                PrincipalId = principalId == Guid.Empty ? null : principalId,
                PerformedBy = performedBy,
                Timestamp = DateTime.UtcNow,
                Details = details
            };

            await _auditRepository.CreateAsync(auditLog, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write audit log for action {Action} by principal {PrincipalId}", action, principalId);
            // Swallow the exception to prevent audit failures from breaking operations
        }
    }

    /// <inheritdoc />
    public async Task LogAsync(string action, Guid principalId, Dictionary<string, object>? metadata = null, CancellationToken cancellationToken = default)
    {
        var details = metadata != null ? System.Text.Json.JsonSerializer.Serialize(metadata) : null;
        await LogAsync(action, principalId, details, cancellationToken);
    }
}
