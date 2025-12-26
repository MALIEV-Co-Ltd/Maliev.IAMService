using Maliev.IAMService.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Maliev.IAMService.Data.Repositories;

public class ServiceAccountApiKeyRepository : IServiceAccountApiKeyRepository
{
    private readonly IAMDbContext _context;

    public ServiceAccountApiKeyRepository(IAMDbContext context)
    {
        _context = context;
    }

    public async Task<ServiceAccountApiKey?> GetByIdAsync(Guid keyId, CancellationToken cancellationToken = default)
    {
        return await _context.ServiceAccountApiKeys
            .Include(k => k.Principal)
            .FirstOrDefaultAsync(k => k.KeyId == keyId && k.IsActive, cancellationToken);
    }

    public async Task<ServiceAccountApiKey?> GetByPrefixAsync(string keyPrefix, CancellationToken cancellationToken = default)
    {
        return await _context.ServiceAccountApiKeys
            .Include(k => k.Principal)
            .FirstOrDefaultAsync(k => k.KeyPrefix == keyPrefix && k.IsActive, cancellationToken);
    }

    public async Task<IEnumerable<ServiceAccountApiKey>> GetByPrincipalIdAsync(Guid principalId, CancellationToken cancellationToken = default)
    {
        return await _context.ServiceAccountApiKeys
            .Where(k => k.PrincipalId == principalId && k.IsActive)
            .OrderByDescending(k => k.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    public async Task<ServiceAccountApiKey> CreateAsync(ServiceAccountApiKey apiKey, CancellationToken cancellationToken = default)
    {
        _context.ServiceAccountApiKeys.Add(apiKey);
        await _context.SaveChangesAsync(cancellationToken);
        return apiKey;
    }

    public async Task UpdateAsync(ServiceAccountApiKey apiKey, CancellationToken cancellationToken = default)
    {
        _context.ServiceAccountApiKeys.Update(apiKey);
        await _context.SaveChangesAsync(cancellationToken);
    }

    public async Task DeactivateAsync(Guid keyId, CancellationToken cancellationToken = default)
    {
        var key = await _context.ServiceAccountApiKeys.FindAsync(new object[] { keyId }, cancellationToken);
        if (key != null)
        {
            key.IsActive = false;
            await _context.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task DeactivateByPrincipalIdAsync(Guid principalId, CancellationToken cancellationToken = default)
    {
        var keys = await _context.ServiceAccountApiKeys
            .Where(k => k.PrincipalId == principalId && k.IsActive)
            .ToListAsync(cancellationToken);

        foreach (var key in keys)
        {
            key.IsActive = false;
        }

        await _context.SaveChangesAsync(cancellationToken);
    }
}
