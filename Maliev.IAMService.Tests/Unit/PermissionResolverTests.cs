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
}
