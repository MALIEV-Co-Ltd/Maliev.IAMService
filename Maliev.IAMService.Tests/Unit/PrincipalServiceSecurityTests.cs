using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Application.Services;
using Maliev.IAMService.Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Maliev.IAMService.Tests.Unit;

/// <summary>
/// Verifies that service identities are resolved only from explicitly provisioned IAM state.
/// </summary>
public sealed class PrincipalServiceSecurityTests
{
    /// <summary>
    /// An unknown service subject must not create a principal or acquire privileged bindings as a side effect.
    /// </summary>
    [Fact]
    public async Task ResolvePrincipalIdAsync_UnknownServiceSubject_FailsClosedWithoutMutation()
    {
        var fixture = CreateFixture();
        fixture.Principals
            .Setup(repository => repository.GetByEmailAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Principal?)null);
        fixture.Principals
            .Setup(repository => repository.CreateAsync(It.IsAny<Principal>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Principal principal, CancellationToken _) => principal);
        fixture.Bindings
            .Setup(repository => repository.GetByPrincipalAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Service.ResolvePrincipalIdAsync("system:service:unknown"));

        fixture.Principals.Verify(
            repository => repository.CreateAsync(It.IsAny<Principal>(), It.IsAny<CancellationToken>()),
            Times.Never);
        fixture.Bindings.Verify(
            repository => repository.CreateAsync(It.IsAny<PrincipalRoleBinding>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    /// <summary>
    /// Resolving a pre-provisioned service principal must not repair it into platform-owner authority.
    /// </summary>
    [Fact]
    public async Task ResolvePrincipalIdAsync_PreProvisionedServicePrincipal_DoesNotGrantPlatformOwner()
    {
        const string subject = "system:service:pricing";
        var principal = new Principal
        {
            PrincipalId = Guid.NewGuid(),
            PrincipalType = "system",
            Email = $"{subject}@serviceaccount.maliev.local",
            IsActive = true
        };
        var fixture = CreateFixture();
        fixture.Principals
            .Setup(repository => repository.GetByEmailAsync(subject, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Principal?)null);
        fixture.Principals
            .Setup(repository => repository.GetByEmailAsync(principal.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(principal);
        fixture.Bindings
            .Setup(repository => repository.GetByPrincipalAsync(principal.PrincipalId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        fixture.Roles
            .Setup(repository => repository.GetByIdAsync("roles.platform.owner", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Role { RoleId = "roles.platform.owner" });

        var resolved = await fixture.Service.ResolvePrincipalIdAsync(subject);

        Assert.Equal(principal.PrincipalId, resolved);
        fixture.Bindings.Verify(
            repository => repository.CreateAsync(It.IsAny<PrincipalRoleBinding>(), It.IsAny<CancellationToken>()),
            Times.Never);
        fixture.Roles.Verify(
            repository => repository.GetByIdAsync("roles.platform.owner", It.IsAny<CancellationToken>()),
            Times.Never);
    }

    private static Fixture CreateFixture()
    {
        var principals = new Mock<IPrincipalRepository>();
        var apiKeys = new Mock<IServiceAccountApiKeyRepository>();
        var bindings = new Mock<IBindingRepository>();
        var roles = new Mock<IRoleRepository>();
        var permissions = new Mock<IPermissionRepository>();
        var cache = new Mock<ICacheService>();
        var audit = new Mock<IAuditService>();
        cache
            .Setup(service => service.GetAsync<Guid?>(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid?)null);
        cache
            .Setup(service => service.SetAsync(
                It.IsAny<string>(),
                It.IsAny<Guid>(),
                It.IsAny<TimeSpan>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var service = new PrincipalService(
            principals.Object,
            apiKeys.Object,
            bindings.Object,
            roles.Object,
            permissions.Object,
            cache.Object,
            audit.Object,
            new ConfigurationBuilder().Build(),
            NullLogger<PrincipalService>.Instance);

        return new Fixture(service, principals, bindings, roles);
    }

    private sealed record Fixture(
        PrincipalService Service,
        Mock<IPrincipalRepository> Principals,
        Mock<IBindingRepository> Bindings,
        Mock<IRoleRepository> Roles);
}
