using Microsoft.EntityFrameworkCore;
using Maliev.IAMService.Data.Entities;

namespace Maliev.IAMService.Data.Repositories;

public class PrincipalRepository : IPrincipalRepository
{
    private readonly IAMDbContext _context;

    public PrincipalRepository(IAMDbContext context)
    {
        _context = context;
    }

    public async Task<Principal?> GetByIdAsync(Guid principalId, CancellationToken cancellationToken = default)
    {
        return await _context.Principals
            .Include(p => p.RoleBindings)
            .FirstOrDefaultAsync(p => p.PrincipalId == principalId, cancellationToken);
    }

    public async Task<Principal?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        return await _context.Principals
            .Include(p => p.RoleBindings)
            .FirstOrDefaultAsync(p => p.Email == email, cancellationToken);
    }

    public async Task<Principal?> GetByLinkedEntityAsync(string linkedService, Guid linkedEntityId, CancellationToken cancellationToken = default)
    {
        return await _context.Principals
            .Include(p => p.RoleBindings)
            .FirstOrDefaultAsync(p => p.LinkedService == linkedService && p.LinkedEntityId == linkedEntityId, cancellationToken);
    }

    public async Task<IEnumerable<Principal>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Principals
            .Include(p => p.RoleBindings)
            .ToListAsync(cancellationToken);
    }

    public async Task<Principal> CreateAsync(Principal principal, CancellationToken cancellationToken = default)
    {
        _context.Principals.Add(principal);
        await _context.SaveChangesAsync(cancellationToken);
        return principal;
    }

    public async Task UpdateAsync(Principal principal, CancellationToken cancellationToken = default)
    {
        principal.UpdatedAt = DateTime.UtcNow;
        _context.Principals.Update(principal);
        await _context.SaveChangesAsync(cancellationToken);
    }

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
