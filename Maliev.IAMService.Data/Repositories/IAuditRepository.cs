using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

public interface IAuditRepository
{
    Task<IAMAuditLog> CreateAsync(IAMAuditLog auditLog, CancellationToken cancellationToken = default);
    Task<IEnumerable<IAMAuditLog>> GetAllAsync(int skip, int take, CancellationToken cancellationToken = default);
    Task<IEnumerable<IAMAuditLog>> GetByPrincipalAsync(Guid principalId, CancellationToken cancellationToken = default);
    Task<IEnumerable<IAMAuditLog>> GetByActionAsync(string action, CancellationToken cancellationToken = default);
    Task<IEnumerable<IAMAuditLog>> GetByDateRangeAsync(DateTime from, DateTime to, CancellationToken cancellationToken = default);
}
