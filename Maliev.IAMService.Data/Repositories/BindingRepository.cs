using Maliev.IAMService.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Maliev.IAMService.Data.Repositories;

/// <summary>
/// Repository implementation for principal-role binding operations.
/// </summary>
public class BindingRepository : IBindingRepository
{
    private readonly IAMDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="BindingRepository"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public BindingRepository(IAMDbContext context) => _context = context;

    /// <inheritdoc/>
    public async Task<PrincipalRoleBinding?> GetByIdAsync(Guid bindingId, CancellationToken cancellationToken = default) =>
        await _context.PrincipalRoleBindings.Include(prb => prb.Role).ThenInclude(r => r.RolePermissions)
            .FirstOrDefaultAsync(prb => prb.BindingId == bindingId, cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<PrincipalRoleBinding>> GetByPrincipalAsync(Guid principalId, CancellationToken cancellationToken = default) =>
        await _context.PrincipalRoleBindings.Include(prb => prb.Role).ThenInclude(r => r.RolePermissions)
            .Where(prb => prb.PrincipalId == principalId && (prb.ExpiresAt == null || prb.ExpiresAt > DateTime.UtcNow))
            .ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task<PrincipalRoleBinding> CreateAsync(PrincipalRoleBinding binding, CancellationToken cancellationToken = default)
    {
        _context.PrincipalRoleBindings.Add(binding);
        await _context.SaveChangesAsync(cancellationToken);
        return binding;
    }

    /// <inheritdoc/>
    public async Task DeleteAsync(Guid bindingId, CancellationToken cancellationToken = default)
    {
        var binding = await _context.PrincipalRoleBindings.FindAsync(new object[] { bindingId }, cancellationToken);
        if (binding != null)
        {
            _context.PrincipalRoleBindings.Remove(binding);
            await _context.SaveChangesAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
    public async Task<bool> ExistsAsync(Guid principalId, string roleId, string? resourcePath, CancellationToken cancellationToken = default) =>
        await _context.PrincipalRoleBindings.AnyAsync(prb =>
            prb.PrincipalId == principalId &&
            prb.RoleId == roleId &&
            prb.ResourcePath == resourcePath, cancellationToken);

    /// <inheritdoc/>
    public async Task<IEnumerable<PrincipalRoleBinding>> GetExpiredBindingsAsync(CancellationToken cancellationToken = default) =>
        await _context.PrincipalRoleBindings.Where(prb => prb.ExpiresAt != null && prb.ExpiresAt <= DateTime.UtcNow)
            .ToListAsync(cancellationToken);

    /// <inheritdoc/>
    public async Task DeleteExpiredBindingsAsync(CancellationToken cancellationToken = default)
    {
        var expiredBindings = await GetExpiredBindingsAsync(cancellationToken);
        _context.PrincipalRoleBindings.RemoveRange(expiredBindings);
        await _context.SaveChangesAsync(cancellationToken);
    }
}
