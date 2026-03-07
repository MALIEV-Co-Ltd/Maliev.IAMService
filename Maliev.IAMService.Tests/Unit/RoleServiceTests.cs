using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Application.Services;
using Maliev.IAMService.Domain.Entities;
using MassTransit;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Maliev.IAMService.Tests.Unit;

public class RoleServiceTests
{
    private readonly Mock<IRoleRepository> _roleRepositoryMock;
    private readonly Mock<IPermissionRepository> _permissionRepositoryMock;
    private readonly Mock<ICacheService> _cacheServiceMock;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly Mock<IPublishEndpoint> _publishEndpointMock;
    private readonly NullLogger<RoleService> _logger;

    public RoleServiceTests()
    {
        _roleRepositoryMock = new Mock<IRoleRepository>();
        _permissionRepositoryMock = new Mock<IPermissionRepository>();
        _cacheServiceMock = new Mock<ICacheService>();
        _auditServiceMock = new Mock<IAuditService>();
        _publishEndpointMock = new Mock<IPublishEndpoint>();
        _logger = NullLogger<RoleService>.Instance;
    }

    private RoleService CreateService()
    {
        return new RoleService(
            _roleRepositoryMock.Object,
            _permissionRepositoryMock.Object,
            _cacheServiceMock.Object,
            _auditServiceMock.Object,
            _publishEndpointMock.Object,
            _logger);
    }

    [Fact]
    public async Task GetAllAsync_ReturnsMappedRoles()
    {
        var service = CreateService();
        var roles = new List<Role>
        {
            new() { RoleId = "roles.test.admin", RoleName = "Admin", ServiceName = "test", IsCustom = true }
        };
        _roleRepositoryMock.Setup(r => r.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(roles);

        var result = await service.GetAllAsync();

        Assert.Single(result);
        Assert.Equal("roles.test.admin", result.First().RoleId);
    }

    [Fact]
    public async Task GetByIdAsync_WhenExists_ReturnsRole()
    {
        var service = CreateService();
        var role = new Role { RoleId = "roles.test.admin", RoleName = "Admin", ServiceName = "test" };
        _roleRepositoryMock.Setup(r => r.GetByIdAsync("roles.test.admin", It.IsAny<CancellationToken>()))
            .ReturnsAsync(role);

        var result = await service.GetByIdAsync("roles.test.admin");

        Assert.NotNull(result);
        Assert.Equal("roles.test.admin", result.RoleId);
    }

    [Fact]
    public async Task GetByIdAsync_WhenNotExists_ReturnsNull()
    {
        var service = CreateService();
        _roleRepositoryMock.Setup(r => r.GetByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Role?)null);

        var result = await service.GetByIdAsync("nonexistent");

        Assert.Null(result);
    }

    [Fact]
    public async Task GetByServiceAsync_ReturnsFilteredRoles()
    {
        var service = CreateService();
        var roles = new List<Role>
        {
            new() { RoleId = "roles.myservice.admin", ServiceName = "myservice" }
        };
        _roleRepositoryMock.Setup(r => r.GetByServiceAsync("myservice", It.IsAny<CancellationToken>()))
            .ReturnsAsync(roles);

        var result = await service.GetByServiceAsync("myservice");

        Assert.Single(result);
    }
}
