using System.Text.Json;

using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Application.Services;
using Maliev.IAMService.Domain.Entities;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Maliev.IAMService.Tests.Unit;

/// <summary>
/// Tests authoritative and cached permission resolution behavior.
/// </summary>
public sealed class PermissionResolverTests
{
    /// <summary>
    /// Aspire's camel-case live-check payload must bind the additive bypass flag at the IAM boundary.
    /// </summary>
    [Fact]
    public void CheckPermissionRequest_DeserializesCamelCaseBypassCache()
    {
        const string json =
            """{"principalId":"principal-123","permissionId":"project.projects.read","resourcePath":"projects/project-123","bypassCache":true}""";

        var request = JsonSerializer.Deserialize<CheckPermissionRequest>(json, JsonSerializerOptions.Web);

        Assert.NotNull(request);
        Assert.Equal("principal-123", request.PrincipalId);
        Assert.Equal("project.projects.read", request.PermissionId);
        Assert.Equal("projects/project-123", request.ResourcePath);
        Assert.True(request.BypassCache);
    }

    /// <summary>
    /// An authoritative empty result must evict a stale cached grant so later standard checks also deny.
    /// </summary>
    [Fact]
    public async Task CheckPermissionAsync_BypassCacheEmptyResult_EvictsStaleGrantForSubsequentChecks()
    {
        var principalId = Guid.NewGuid();
        const string permissionId = "project.projects.read";
        const string resourcePath = "projects/project-123";
        var expectedCacheKey = IamPermissionCacheKeys.ForPermissions(principalId, resourcePath);
        var bindingRepository = new Mock<IBindingRepository>();
        bindingRepository
            .Setup(repository => repository.GetByPrincipalAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        bindingRepository
            .Setup(repository => repository.GetDirectPermissionsByPrincipalAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        var principalService = new Mock<IPrincipalService>();
        principalService
            .Setup(service => service.ResolvePrincipalIdAsync(principalId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(principalId);
        principalService
            .Setup(service => service.GetByIdAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Principal { PrincipalId = principalId, PrincipalType = "service_account", IsActive = true });
        var staleCacheExists = true;
        var cacheService = new Mock<ICacheService>();
        cacheService
            .Setup(service => service.GetAsync<ResolvePermissionsResponse>(expectedCacheKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => staleCacheExists
                ? new ResolvePermissionsResponse
                {
                    PrincipalId = principalId,
                    Permissions = [permissionId],
                    Roles = [],
                    ResourcePath = resourcePath,
                    FromCache = false
                }
                : null);
        cacheService
            .Setup(service => service.RemoveAsync(expectedCacheKey, It.IsAny<CancellationToken>()))
            .Callback(() => staleCacheExists = false)
            .Returns(Task.CompletedTask);
        var resolver = new PermissionResolver(
            bindingRepository.Object,
            principalService.Object,
            cacheService.Object,
            NullLogger<PermissionResolver>.Instance);

        var liveResponse = await resolver.CheckPermissionAsync(new CheckPermissionRequest
        {
            PrincipalId = principalId.ToString(),
            PermissionId = permissionId,
            ResourcePath = resourcePath,
            BypassCache = true
        });
        var standardResponse = await resolver.CheckPermissionAsync(new CheckPermissionRequest
        {
            PrincipalId = principalId.ToString(),
            PermissionId = permissionId,
            ResourcePath = resourcePath
        });

        Assert.False(liveResponse.Allowed);
        Assert.False(liveResponse.FromCache);
        Assert.False(standardResponse.Allowed);
        Assert.False(standardResponse.FromCache);
        cacheService.Verify(
            service => service.RemoveAsync(expectedCacheKey, It.IsAny<CancellationToken>()),
            Times.Once);
        bindingRepository.Verify(
            repository => repository.GetByPrincipalAsync(principalId, It.IsAny<CancellationToken>()),
            Times.Exactly(2));
    }

    /// <summary>
    /// Authority snapshots from the pre-hardening namespace must never be reused after the cutover.
    /// </summary>
    [Fact]
    public async Task CheckPermissionAsync_PreHardeningWildcardCache_IsIgnored()
    {
        var principalId = Guid.NewGuid();
        var bindingRepository = new Mock<IBindingRepository>();
        bindingRepository
            .Setup(repository => repository.GetByPrincipalAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        bindingRepository
            .Setup(repository => repository.GetDirectPermissionsByPrincipalAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        var principalService = new Mock<IPrincipalService>();
        principalService
            .Setup(service => service.ResolvePrincipalIdAsync(principalId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(principalId);
        principalService
            .Setup(service => service.GetByIdAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Principal { PrincipalId = principalId, PrincipalType = "service_account", IsActive = true });
        var legacyKey = $"iam:principal:{principalId}:permissions";
        var cacheService = new Mock<ICacheService>();
        cacheService
            .Setup(service => service.GetAsync<ResolvePermissionsResponse>(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string key, CancellationToken _) => key == legacyKey
                ? new ResolvePermissionsResponse
                {
                    PrincipalId = principalId,
                    Permissions = ["*"],
                    Roles = ["roles.platform.owner"],
                    FromCache = false
                }
                : null);
        var resolver = new PermissionResolver(
            bindingRepository.Object,
            principalService.Object,
            cacheService.Object,
            NullLogger<PermissionResolver>.Instance);

        var response = await resolver.CheckPermissionAsync(new CheckPermissionRequest
        {
            PrincipalId = principalId.ToString(),
            PermissionId = "iam.workload-principals.provision"
        });

        Assert.False(response.Allowed);
        Assert.False(response.FromCache);
        cacheService.Verify(
            service => service.GetAsync<ResolvePermissionsResponse>(
                IamPermissionCacheKeys.ForPermissions(principalId),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    /// <summary>
    /// A live permission check must ignore a stale Redis result and read current bindings.
    /// </summary>
    [Fact]
    public async Task CheckPermissionAsync_BypassCache_ReadsAuthoritativeBindings()
    {
        var principalId = Guid.NewGuid();
        var bindingRepository = new Mock<IBindingRepository>();
        bindingRepository
            .Setup(repository => repository.GetByPrincipalAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        bindingRepository
            .Setup(repository => repository.GetDirectPermissionsByPrincipalAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        var principalService = new Mock<IPrincipalService>();
        principalService
            .Setup(service => service.ResolvePrincipalIdAsync(principalId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(principalId);
        principalService
            .Setup(service => service.GetByIdAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Principal { PrincipalId = principalId, PrincipalType = "service_account", IsActive = true });
        var cacheService = new Mock<ICacheService>();
        cacheService
            .Setup(service => service.GetAsync<ResolvePermissionsResponse>(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ResolvePermissionsResponse
            {
                PrincipalId = principalId,
                Permissions = ["project.projects.read"],
                Roles = [],
                ResourcePath = "projects/project-123",
                FromCache = false
            });
        var resolver = new PermissionResolver(
            bindingRepository.Object,
            principalService.Object,
            cacheService.Object,
            NullLogger<PermissionResolver>.Instance);
        var request = new CheckPermissionRequest
        {
            PrincipalId = principalId.ToString(),
            PermissionId = "project.projects.read",
            ResourcePath = "projects/project-123",
            BypassCache = true
        };

        var response = await resolver.CheckPermissionAsync(request);

        Assert.False(response.Allowed);
        Assert.False(response.FromCache);
        cacheService.Verify(
            service => service.GetAsync<ResolvePermissionsResponse>(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
        bindingRepository.Verify(
            repository => repository.GetByPrincipalAsync(principalId, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    /// <summary>
    /// Token issuance must not preserve a revoked authority from the normal permission cache.
    /// </summary>
    [Fact]
    public async Task ResolvePermissionsForTokenIssuanceAsync_StaleGrant_ReadsAuthoritativeBindingsAndEvictsCache()
    {
        var principalId = Guid.NewGuid();
        var expectedCacheKey = IamPermissionCacheKeys.ForPermissions(principalId);
        var bindingRepository = new Mock<IBindingRepository>();
        bindingRepository
            .Setup(repository => repository.GetByPrincipalAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        bindingRepository
            .Setup(repository => repository.GetDirectPermissionsByPrincipalAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        var principalService = new Mock<IPrincipalService>();
        principalService
            .Setup(service => service.ResolvePrincipalIdAsync(principalId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(principalId);
        principalService
            .Setup(service => service.GetByIdAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Principal { PrincipalId = principalId, PrincipalType = "employee", IsActive = true });
        var cacheService = new Mock<ICacheService>();
        cacheService
            .Setup(service => service.GetAsync<ResolvePermissionsResponse>(expectedCacheKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ResolvePermissionsResponse
            {
                PrincipalId = principalId,
                Permissions = ["iam.roles.assign"],
                Roles = ["roles.platform.owner"],
                FromCache = false
            });
        var resolver = new PermissionResolver(
            bindingRepository.Object,
            principalService.Object,
            cacheService.Object,
            NullLogger<PermissionResolver>.Instance);

        var response = await resolver.ResolvePermissionsForTokenIssuanceAsync(new ResolvePermissionsRequest
        {
            PrincipalId = principalId.ToString()
        });

        Assert.Empty(response.Permissions);
        Assert.Empty(response.Roles);
        Assert.False(response.FromCache);
        cacheService.Verify(
            service => service.GetAsync<ResolvePermissionsResponse>(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
        cacheService.Verify(
            service => service.RemoveAsync(expectedCacheKey, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    /// <summary>
    /// Inactive principals must be denied before a previously cached grant can be returned.
    /// </summary>
    [Fact]
    public async Task CheckPermissionAsync_InactivePrincipal_DeniesAndEvictsCachedAuthority()
    {
        var principalId = Guid.NewGuid();
        var bindingRepository = new Mock<IBindingRepository>();
        var principalService = new Mock<IPrincipalService>();
        principalService
            .Setup(service => service.ResolvePrincipalIdAsync(principalId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(principalId);
        principalService
            .Setup(service => service.GetByIdAsync(principalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Principal { PrincipalId = principalId, PrincipalType = "service_account", IsActive = false });
        var cacheService = new Mock<ICacheService>();
        cacheService
            .Setup(service => service.GetAsync<ResolvePermissionsResponse>(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ResolvePermissionsResponse
            {
                PrincipalId = principalId,
                Permissions = ["project.projects.read"],
                Roles = [],
                FromCache = false
            });
        var resolver = new PermissionResolver(
            bindingRepository.Object,
            principalService.Object,
            cacheService.Object,
            NullLogger<PermissionResolver>.Instance);

        var response = await resolver.CheckPermissionAsync(new CheckPermissionRequest
        {
            PrincipalId = principalId.ToString(),
            PermissionId = "project.projects.read"
        });

        Assert.False(response.Allowed);
        Assert.False(response.FromCache);
        cacheService.Verify(
            service => service.GetAsync<ResolvePermissionsResponse>(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
        cacheService.Verify(
            service => service.RemoveByPrefixAsync(
                IamPermissionCacheKeys.ForPermissions(principalId),
                It.IsAny<CancellationToken>()),
            Times.Once);
        bindingRepository.Verify(
            service => service.GetByPrincipalAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }
}
