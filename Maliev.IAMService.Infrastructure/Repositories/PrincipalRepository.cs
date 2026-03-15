using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Maliev.IAMService.Infrastructure.Repositories;

/// <summary>
/// Repository implementation for principal operations.
/// </summary>
public class PrincipalRepository : IPrincipalRepository
{
    private readonly IAMDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="PrincipalRepository"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public PrincipalRepository(IAMDbContext context)
    {
        _context = context;
    }

    /// <inheritdoc/>
    public async Task<Principal?> GetByIdAsync(Guid principalId, CancellationToken cancellationToken = default)
    {
        return await _context.Principals
            .Include(p => p.RoleBindings)
            .Include(p => p.PermissionBindings)
            .AsSplitQuery()
            .FirstOrDefaultAsync(p => p.PrincipalId == principalId, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<Principal?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        return await _context.Principals
            .Include(p => p.RoleBindings)
            .Include(p => p.PermissionBindings)
            .AsSplitQuery()
            .FirstOrDefaultAsync(p => p.Email == email, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<Principal?> GetByLinkedEntityAsync(string linkedService, Guid linkedEntityId, CancellationToken cancellationToken = default)
    {
        return await _context.Principals
            .Include(p => p.RoleBindings)
            .FirstOrDefaultAsync(p => p.LinkedService == linkedService && p.LinkedEntityId == linkedEntityId, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IEnumerable<Principal>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Principals
            .Include(p => p.RoleBindings)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<Principal> CreateAsync(Principal principal, CancellationToken cancellationToken = default)
    {
        _context.Principals.Add(principal);
        try
        {
            await _context.SaveChangesAsync(cancellationToken);
            return principal;
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException pgEx && pgEx.SqlState == "23505")
        {
            _context.Entry(principal).State = EntityState.Detached;
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task UpdateAsync(Principal principal, CancellationToken cancellationToken = default)
    {
        principal.UpdatedAt = DateTime.UtcNow;
        _context.Principals.Update(principal);
        await _context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task DeleteAsync(Guid principalId, CancellationToken cancellationToken = default)
    {
        var principal = await _context.Principals.FindAsync(new object[] { principalId }, cancellationToken);
        if (principal != null)
        {
            _context.Principals.Remove(principal);
            await _context.SaveChangesAsync(cancellationToken);
        }
    }
}
