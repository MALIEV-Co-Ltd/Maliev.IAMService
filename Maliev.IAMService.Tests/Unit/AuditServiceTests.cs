using Maliev.IAMService.Api.Services;
using Maliev.IAMService.Data.Entities;
using Maliev.IAMService.Data.Repositories;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Maliev.IAMService.Tests.Unit;

public class AuditServiceTests
{
    private sealed class ThrowingAuditRepository : IAuditRepository
    {
        public Task<IAMAuditLog> CreateAsync(IAMAuditLog auditLog, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("Simulated DB failure");

        public Task<IEnumerable<IAMAuditLog>> GetAllAsync(int skip, int take, CancellationToken cancellationToken = default)
            => Task.FromResult(Enumerable.Empty<IAMAuditLog>());

        public Task<IEnumerable<IAMAuditLog>> GetByPrincipalAsync(Guid principalId, CancellationToken cancellationToken = default)
            => Task.FromResult(Enumerable.Empty<IAMAuditLog>());

        public Task<IEnumerable<IAMAuditLog>> GetByActionAsync(string action, CancellationToken cancellationToken = default)
            => Task.FromResult(Enumerable.Empty<IAMAuditLog>());

        public Task<IEnumerable<IAMAuditLog>> GetByDateRangeAsync(DateTime from, DateTime to, CancellationToken cancellationToken = default)
            => Task.FromResult(Enumerable.Empty<IAMAuditLog>());
    }

    [Fact]
    public async Task LogAsync_String_WhenRepositoryThrows_DoesNotPropagate()
    {
        var service = new AuditService(new ThrowingAuditRepository(), NullLogger<AuditService>.Instance);

        // Should not throw - exception is swallowed to protect calling operations
        await service.LogAsync("TEST_ACTION", Guid.NewGuid(), "some details");
    }

    [Fact]
    public async Task LogAsync_String_WithEmptyPrincipalId_DoesNotPropagate()
    {
        var service = new AuditService(new ThrowingAuditRepository(), NullLogger<AuditService>.Instance);

        // Guid.Empty triggers the system principal substitution path, then the catch
        await service.LogAsync("TEST_ACTION", Guid.Empty, "details");
    }

    [Fact]
    public async Task LogAsync_Dictionary_WhenRepositoryThrows_DoesNotPropagate()
    {
        var service = new AuditService(new ThrowingAuditRepository(), NullLogger<AuditService>.Instance);

        var metadata = new Dictionary<string, object> { ["key"] = "value" };
        await service.LogAsync("TEST_ACTION", Guid.NewGuid(), metadata);
    }
}
