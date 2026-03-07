using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Maliev.IAMService.Infrastructure.Repositories;

/// <summary>
/// Repository implementation for service account API key operations.
/// </summary>
public class ServiceAccountApiKeyRepository : IServiceAccountApiKeyRepository
{
    private readonly IAMDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="ServiceAccountApiKeyRepository"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public ServiceAccountApiKeyRepository(IAMDbContext context)
    {
        _context = context;
    }

    /// <inheritdoc/>
    public async Task<ServiceAccountApiKey?> GetByIdAsync(Guid keyId, CancellationToken cancellationToken = default)
    {
        return await _context.ServiceAccountApiKeys
            .Include(k => k.Principal)
            .FirstOrDefaultAsync(k => k.KeyId == keyId && k.IsActive, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<ServiceAccountApiKey?> GetByPrefixAsync(string keyPrefix, CancellationToken cancellationToken = default)
    {
        return await _context.ServiceAccountApiKeys
            .Include(k => k.Principal)
            .FirstOrDefaultAsync(k => k.KeyPrefix == keyPrefix && k.IsActive, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IEnumerable<ServiceAccountApiKey>> GetByPrincipalIdAsync(Guid principalId, CancellationToken cancellationToken = default)
    {
        return await _context.ServiceAccountApiKeys
            .Where(k => k.PrincipalId == principalId && k.IsActive)
            .OrderByDescending(k => k.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<ServiceAccountApiKey> CreateAsync(ServiceAccountApiKey apiKey, CancellationToken cancellationToken = default)
    {
        _context.ServiceAccountApiKeys.Add(apiKey);
        await _context.SaveChangesAsync(cancellationToken);
        return apiKey;
    }

    /// <inheritdoc/>
    public async Task UpdateAsync(ServiceAccountApiKey apiKey, CancellationToken cancellationToken = default)
    {
        _context.ServiceAccountApiKeys.Update(apiKey);
        await _context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task DeactivateAsync(Guid keyId, CancellationToken cancellationToken = default)
    {
        var key = await _context.ServiceAccountApiKeys.FindAsync(new object[] { keyId }, cancellationToken);
        if (key != null)
        {
            key.IsActive = false;
            await _context.SaveChangesAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
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
