using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

/// <summary>
/// Interface for auditing repository operations.
/// </summary>
public interface IAuditRepository
{
    /// <summary>
    /// Creates a new audit log entry asynchronously.
    /// </summary>
    /// <param name="auditLog">The audit log entry to create.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The created audit log entry.</returns>
    Task<IAMAuditLog> CreateAsync(IAMAuditLog auditLog, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a paginated list of all audit logs asynchronously.
    /// </summary>
    /// <param name="skip">The number of records to skip.</param>
    /// <param name="take">The number of records to take.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of audit logs.</returns>
    Task<IEnumerable<IAMAuditLog>> GetAllAsync(int skip, int take, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves audit logs associated with a specific principal asynchronously.
    /// </summary>
    /// <param name="principalId">The unique identifier of the principal.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of audit logs.</returns>
    Task<IEnumerable<IAMAuditLog>> GetByPrincipalAsync(Guid principalId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves audit logs for a specific action asynchronously.
    /// </summary>
    /// <param name="action">The action performed.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of audit logs.</returns>
    Task<IEnumerable<IAMAuditLog>> GetByActionAsync(string action, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves audit logs within a specific date range asynchronously.
    /// </summary>
    /// <param name="from">The start date and time.</param>
    /// <param name="to">The end date and time.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of audit logs.</returns>
    Task<IEnumerable<IAMAuditLog>> GetByDateRangeAsync(DateTime from, DateTime to, CancellationToken cancellationToken = default);
}
