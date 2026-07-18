using Maliev.IAMService.Application.Services;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Maliev.IAMService.Tests.Unit;

/// <summary>
/// Verifies that cache best-effort failure handling does not consume caller cancellation.
/// </summary>
public sealed class CacheServiceCancellationTests
{
    /// <summary>
    /// A canceled cache read must remain observable to the caller.
    /// </summary>
    [Fact]
    public async Task GetAsync_CallerCanceled_ThrowsOperationCanceledException()
    {
        using var cancellation = CreateCanceledTokenSource();
        var distributedCache = new Mock<IDistributedCache>();
        distributedCache
            .Setup(cache => cache.GetAsync("permission-key", cancellation.Token))
            .Returns(Task.FromCanceled<byte[]?>(cancellation.Token)!);
        var service = CreateService(distributedCache.Object);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.GetAsync<object>("permission-key", cancellation.Token));
    }

    /// <summary>
    /// A canceled cache write must remain observable to the caller.
    /// </summary>
    [Fact]
    public async Task SetAsync_CallerCanceled_ThrowsOperationCanceledException()
    {
        using var cancellation = CreateCanceledTokenSource();
        var distributedCache = new Mock<IDistributedCache>();
        distributedCache
            .Setup(cache => cache.SetAsync(
                "permission-key",
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                cancellation.Token))
            .Returns(Task.FromCanceled(cancellation.Token));
        var service = CreateService(distributedCache.Object);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.SetAsync("permission-key", new { allowed = true }, cancellationToken: cancellation.Token));
    }

    /// <summary>
    /// A canceled exact-key eviction must remain observable to the caller.
    /// </summary>
    [Fact]
    public async Task RemoveAsync_CallerCanceled_ThrowsOperationCanceledException()
    {
        using var cancellation = CreateCanceledTokenSource();
        var distributedCache = new Mock<IDistributedCache>();
        distributedCache
            .Setup(cache => cache.RemoveAsync("permission-key", cancellation.Token))
            .Returns(Task.FromCanceled(cancellation.Token));
        var service = CreateService(distributedCache.Object);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.RemoveAsync("permission-key", cancellation.Token));
    }

    /// <summary>
    /// Prefix eviction must reject an already-canceled caller even without Redis configured.
    /// </summary>
    [Fact]
    public async Task RemoveByPrefixAsync_CallerAlreadyCanceled_ThrowsOperationCanceledException()
    {
        using var cancellation = CreateCanceledTokenSource();
        var service = CreateService(Mock.Of<IDistributedCache>());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.RemoveByPrefixAsync("iam:principal:test:", cancellation.Token));
    }

    private static CacheService CreateService(IDistributedCache distributedCache) =>
        new(distributedCache, NullLogger<CacheService>.Instance);

    private static CancellationTokenSource CreateCanceledTokenSource()
    {
        var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        return cancellation;
    }
}
