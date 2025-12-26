using Microsoft.EntityFrameworkCore;
using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

public class AuditRepository : IAuditRepository
{
    private readonly IAMDbContext _context;

    public AuditRepository(IAMDbContext context) => _context = context;

    public async Task<IAMAuditLog> CreateAsync(IAMAuditLog auditLog, CancellationToken cancellationToken = default)
    {
        _context.IAMAuditLogs.Add(auditLog);
        await _context.SaveChangesAsync(cancellationToken);
        return auditLog;
    }

    public async Task<IEnumerable<IAMAuditLog>> GetAllAsync(int skip, int take, CancellationToken cancellationToken = default) =>
        await _context.IAMAuditLogs.OrderByDescending(al => al.Timestamp).Skip(skip).Take(take)
            .ToListAsync(cancellationToken);

    public async Task<IEnumerable<IAMAuditLog>> GetByPrincipalAsync(Guid principalId, CancellationToken cancellationToken = default) =>
        await _context.IAMAuditLogs.Where(al => al.PrincipalId == principalId).OrderByDescending(al => al.Timestamp)
            .ToListAsync(cancellationToken);

    public async Task<IEnumerable<IAMAuditLog>> GetByActionAsync(string action, CancellationToken cancellationToken = default) =>
        await _context.IAMAuditLogs.Where(al => al.Action == action).OrderByDescending(al => al.Timestamp)
            .ToListAsync(cancellationToken);

    public async Task<IEnumerable<IAMAuditLog>> GetByDateRangeAsync(DateTime from, DateTime to, CancellationToken cancellationToken = default) =>
        await _context.IAMAuditLogs.Where(al => al.Timestamp >= from && al.Timestamp <= to)
            .OrderByDescending(al => al.Timestamp).ToListAsync(cancellationToken);
}
