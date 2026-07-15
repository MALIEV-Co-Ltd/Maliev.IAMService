using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.Aspire.ServiceDefaults.IAM;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Tests.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Exercises the shared Aspire IAM client through IAM's real HTTP, PostgreSQL, and Redis boundaries.
/// </summary>
[Collection(RedisLivePermissionContractCollection.Name)]
public sealed class AspireIamRedisLivePermissionContractTests
{
    private const string PermissionId = "project.projects.read";
    private const string LogicalCacheKeyPrefix = "iam:principal:";
    private readonly RedisLivePermissionContractFactory _factory;

    /// <summary>Initializes the contract suite with its isolated real-Redis fixture.</summary>
    public AspireIamRedisLivePermissionContractTests(RedisLivePermissionContractFactory factory)
    {
        _factory = factory;
    }

    /// <summary>
    /// Omitting the additive bypass flag must preserve the standard cached-permission contract.
    /// </summary>
    [Fact]
    public async Task CheckPermission_OmittedBypassCache_BindsFalseAndCachesAllow()
    {
        await _factory.ResetContractStateAsync();
        var seeded = await SeedAllowedPrincipalAsync();
        using var transport = CreateCapturedTransport();

        using var response = await transport.Client.PostAsJsonAsync(
            "/iam/v1/auth/check-permission",
            new { principalId = seeded.PrincipalId.ToString(), permissionId = PermissionId });
        var result = await response.Content.ReadFromJsonAsync<CheckPermissionResponse>();

        response.EnsureSuccessStatusCode();
        Assert.NotNull(result);
        Assert.True(result.Allowed);
        Assert.False(result.FromCache);
        Assert.Single(transport.Requests);
        Assert.False(transport.Requests.Single().HasBypassCache);
        Assert.True(await _factory.CacheKeyExistsAsync(CacheKey(seeded.PrincipalId)));
    }

    /// <summary>
    /// A live Aspire check must bypass a stale Redis grant, evict it, and make later standard reads deny.
    /// </summary>
    [Fact]
    public async Task AspireClient_CachedAllowThenMissedInvalidation_LiveDenyEvictsRedisAndRawStandardDenies()
    {
        await _factory.ResetContractStateAsync();
        var seeded = await SeedAllowedPrincipalAsync();
        using var transport = CreateCapturedTransport();
        var aspireClient = CreateAspireClient(transport.Client);

        Assert.True(await aspireClient.CheckPermissionAsync(seeded.PrincipalId.ToString(), PermissionId));

        using (var cachedResponse = await transport.Client.PostAsJsonAsync(
            "/iam/v1/auth/check-permission",
            Request(seeded.PrincipalId, bypassCache: false)))
        {
            var cachedResult = await cachedResponse.Content.ReadFromJsonAsync<CheckPermissionResponse>();
            cachedResponse.EnsureSuccessStatusCode();
            Assert.NotNull(cachedResult);
            Assert.True(cachedResult.Allowed);
            Assert.True(cachedResult.FromCache);
        }

        Assert.True(await _factory.CacheKeyExistsAsync(CacheKey(seeded.PrincipalId)));
        await DeleteBindingWithoutCacheInvalidationAsync(seeded.BindingId);
        Assert.True(await _factory.CacheKeyExistsAsync(CacheKey(seeded.PrincipalId)));

        Assert.False(await aspireClient.CheckPermissionLiveAsync(seeded.PrincipalId.ToString(), PermissionId));
        Assert.False(await _factory.CacheKeyExistsAsync(CacheKey(seeded.PrincipalId)));

        using var standardResponse = await transport.Client.PostAsJsonAsync(
            "/iam/v1/auth/check-permission",
            Request(seeded.PrincipalId, bypassCache: false));
        var standardResult = await standardResponse.Content.ReadFromJsonAsync<CheckPermissionResponse>();

        standardResponse.EnsureSuccessStatusCode();
        Assert.NotNull(standardResult);
        Assert.False(standardResult.Allowed);
        Assert.False(standardResult.FromCache);
        Assert.Equal([false, false, true, false], transport.Requests.Select(request => request.BypassCache));
        Assert.All(transport.Requests, request => Assert.True(request.HasBypassCache));
    }

    /// <summary>
    /// Concurrent authoritative checks must converge the shared client, IAM, and Redis caches on denial.
    /// </summary>
    [Fact]
    public async Task AspireClient_ConcurrentLiveChecksAfterRevoke_ConvergeOnDenial()
    {
        await _factory.ResetContractStateAsync();
        var seeded = await SeedAllowedPrincipalAsync();
        using var transport = CreateCapturedTransport();
        var aspireClient = CreateAspireClient(transport.Client);

        Assert.True(await aspireClient.CheckPermissionAsync(seeded.PrincipalId.ToString(), PermissionId));
        await DeleteBindingWithoutCacheInvalidationAsync(seeded.BindingId);

        var liveResults = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ =>
            aspireClient.CheckPermissionLiveAsync(seeded.PrincipalId.ToString(), PermissionId)));
        var standardResults = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ =>
            aspireClient.CheckPermissionAsync(seeded.PrincipalId.ToString(), PermissionId)));
        var rawResponses = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            transport.Client.PostAsJsonAsync(
                "/iam/v1/auth/check-permission",
                Request(seeded.PrincipalId, bypassCache: false))));

        try
        {
            Assert.All(liveResults, Assert.False);
            Assert.All(standardResults, Assert.False);
            Assert.All(rawResponses, response => response.EnsureSuccessStatusCode());
            var rawResults = await Task.WhenAll(rawResponses.Select(response =>
                response.Content.ReadFromJsonAsync<CheckPermissionResponse>()));
            Assert.All(rawResults, result =>
            {
                Assert.NotNull(result);
                Assert.False(result.Allowed);
            });
            Assert.False(await _factory.CacheKeyExistsAsync(CacheKey(seeded.PrincipalId)));
        }
        finally
        {
            foreach (var response in rawResponses)
            {
                response.Dispose();
            }
        }
    }

    /// <summary>
    /// Canceling a live Aspire check must propagate cancellation instead of becoming an ordinary denial.
    /// </summary>
    [Fact]
    public async Task AspireClient_LiveCheckCallerCanceled_PropagatesCancellationWithoutRequest()
    {
        await _factory.ResetContractStateAsync();
        var seeded = await SeedAllowedPrincipalAsync();
        using var transport = CreateCapturedTransport();
        var aspireClient = CreateAspireClient(transport.Client);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            aspireClient.CheckPermissionLiveAsync(
                seeded.PrincipalId.ToString(),
                PermissionId,
                cancellationToken: cancellation.Token));

        Assert.Empty(transport.Requests);
        Assert.False(await _factory.CacheKeyExistsAsync(CacheKey(seeded.PrincipalId)));
    }

    private async Task<SeededPermission> SeedAllowedPrincipalAsync()
    {
        var principalId = Guid.NewGuid();
        var bindingId = Guid.NewGuid();
        var roleId = $"roles.ops67.reader-{Guid.NewGuid():N}";
        await using var context = _factory.CreateDbContext();
        context.AddRange(
            new Principal
            {
                PrincipalId = principalId,
                PrincipalType = "user",
                Email = $"ops67-{principalId:N}@example.test"
            },
            new Permission
            {
                PermissionId = PermissionId,
                ServiceName = "project",
                ResourceType = "projects",
                Action = "read"
            },
            new Role
            {
                RoleId = roleId,
                RoleName = "Ops 67 Redis reader",
                ServiceName = "project"
            });
        context.RolePermissions.Add(new RolePermission
        {
            RoleId = roleId,
            PermissionId = PermissionId
        });
        context.PrincipalRoleBindings.Add(new PrincipalRoleBinding
        {
            BindingId = bindingId,
            PrincipalId = principalId,
            RoleId = roleId,
            GrantedBy = Guid.NewGuid()
        });
        await context.SaveChangesAsync();
        return new SeededPermission(principalId, bindingId);
    }

    private async Task DeleteBindingWithoutCacheInvalidationAsync(Guid bindingId)
    {
        await using var context = _factory.CreateDbContext();
        var binding = await context.PrincipalRoleBindings.SingleAsync(candidate => candidate.BindingId == bindingId);
        context.PrincipalRoleBindings.Remove(binding);
        await context.SaveChangesAsync();
    }

    private CapturedTransport CreateCapturedTransport()
    {
        var handler = new RequestCaptureHandler(_factory.Server.CreateHandler());
        var client = new HttpClient(handler)
        {
            BaseAddress = _factory.Server.BaseAddress
        };
        var token = _factory.CreateTestJwtToken(
            "system:service:intranetbff",
            roles: ["service-account"],
            permissions: ["iam.auth.check-permission"],
            additionalClaims: new Dictionary<string, string>
            {
                ["service_name"] = "IntranetBff",
                ["user_type"] = "service",
                ["purpose"] = "iam-registration"
            });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return new CapturedTransport(client, handler.Requests);
    }

    private IamServiceClient CreateAspireClient(HttpClient client)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["IAM:LivePermissionChecks:Credential"] = RedisLivePermissionContractFactory.LiveCheckCredential
            })
            .Build();
        return new IamServiceClient(
            new StaticHttpClientFactory(client),
            NullLogger<IamServiceClient>.Instance,
            _factory.Services.GetRequiredService<IHostEnvironment>(),
            configuration);
    }

    private static CheckPermissionRequest Request(Guid principalId, bool bypassCache) => new()
    {
        PrincipalId = principalId.ToString(),
        PermissionId = PermissionId,
        BypassCache = bypassCache
    };

    private static string CacheKey(Guid principalId) =>
        $"{LogicalCacheKeyPrefix}{principalId}:permissions";

    private sealed record SeededPermission(Guid PrincipalId, Guid BindingId);

    private sealed record CapturedRequest(bool HasBypassCache, bool BypassCache);

    private sealed class CapturedTransport(HttpClient client, ConcurrentQueue<CapturedRequest> requests) : IDisposable
    {
        public HttpClient Client { get; } = client;

        public ConcurrentQueue<CapturedRequest> Requests { get; } = requests;

        public void Dispose() => Client.Dispose();
    }

    private sealed class RequestCaptureHandler(HttpMessageHandler innerHandler) : DelegatingHandler(innerHandler)
    {
        public ConcurrentQueue<CapturedRequest> Requests { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.Content is not null
                && request.RequestUri?.AbsolutePath.EndsWith("/check-permission", StringComparison.Ordinal) == true)
            {
                var payload = await request.Content.ReadFromJsonAsync<JsonElement>(cancellationToken);
                var hasBypassCache = payload.TryGetProperty("bypassCache", out var bypassCache);
                Requests.Enqueue(new CapturedRequest(
                    hasBypassCache,
                    hasBypassCache && bypassCache.GetBoolean()));
            }

            return await base.SendAsync(request, cancellationToken);
        }
    }

    private sealed class StaticHttpClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }
}
