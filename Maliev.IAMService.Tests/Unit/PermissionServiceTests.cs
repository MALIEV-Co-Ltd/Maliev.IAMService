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

public class PermissionServiceTests
{
    private readonly Mock<IPermissionRepository> _permissionRepositoryMock;
    private readonly Mock<IPublishEndpoint> _publishEndpointMock;
    private readonly NullLogger<PermissionService> _logger;

    public PermissionServiceTests()
    {
        _permissionRepositoryMock = new Mock<IPermissionRepository>();
        _publishEndpointMock = new Mock<IPublishEndpoint>();
        _logger = NullLogger<PermissionService>.Instance;
    }

    private PermissionService CreateService()
    {
        return new PermissionService(
            _permissionRepositoryMock.Object,
            _publishEndpointMock.Object,
            _logger);
    }

    [Fact]
    public async Task GetAllAsync_ReturnsMappedPermissions()
    {
        var service = CreateService();
        var permissions = new List<Permission>
        {
            new() { PermissionId = "test.read", ServiceName = "test", ResourceType = "read", Action = "test", Description = "Read" }
        };
        _permissionRepositoryMock.Setup(r => r.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(permissions);

        var result = await service.GetAllAsync();

        Assert.Single(result);
        Assert.Equal("test.read", result.First().PermissionId);
    }

    [Fact]
    public async Task GetByServiceAsync_ReturnsFilteredPermissions()
    {
        var service = CreateService();
        var permissions = new List<Permission>
        {
            new() { PermissionId = "myservice.read", ServiceName = "myservice", ResourceType = "read", Action = "myservice" }
        };
        _permissionRepositoryMock.Setup(r => r.GetByServiceAsync("myservice", It.IsAny<CancellationToken>()))
            .ReturnsAsync(permissions);

        var result = await service.GetByServiceAsync("myservice");

        Assert.Single(result);
    }

    [Fact]
    public async Task GetByIdAsync_WhenExists_ReturnsPermission()
    {
        var service = CreateService();
        var permission = new Permission { PermissionId = "test.read", ServiceName = "test", ResourceType = "read", Action = "test" };
        _permissionRepositoryMock.Setup(r => r.GetByIdAsync("test.read", It.IsAny<CancellationToken>()))
            .ReturnsAsync(permission);

        var result = await service.GetByIdAsync("test.read");

        Assert.NotNull(result);
        Assert.Equal("test.read", result.PermissionId);
    }

    [Fact]
    public async Task GetByIdAsync_WhenNotExists_ReturnsNull()
    {
        var service = CreateService();
        _permissionRepositoryMock.Setup(r => r.GetByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Permission?)null);

        var result = await service.GetByIdAsync("nonexistent");

        Assert.Null(result);
    }

    [Fact]
    public async Task RegisterPermissionsAsync_WithInvalidServiceName_ThrowsArgumentException()
    {
        var service = CreateService();
        var request = new RegisterPermissionsRequest
        {
            ServiceName = "",
            Permissions = new List<PermissionDto>()
        };

        await Assert.ThrowsAsync<ArgumentException>(() => service.RegisterPermissionsAsync(request));
    }

    [Fact]
    public async Task RegisterPermissionsAsync_WithInvalidPermissionFormat_SkipsInvalid()
    {
        var service = CreateService();
        _permissionRepositoryMock.Setup(r => r.GetByServiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<Permission>());

        var request = new RegisterPermissionsRequest
        {
            ServiceName = "test-service",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = "Invalid_Permission", Description = "Test" }
            }
        };

        var result = await service.RegisterPermissionsAsync(request);

        Assert.Empty(result);
    }

    [Fact]
    public async Task RegisterPermissionsAsync_WithServiceMismatch_SkipsInvalid()
    {
        var service = CreateService();
        _permissionRepositoryMock.Setup(r => r.GetByServiceAsync("test-service", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<Permission>());

        var request = new RegisterPermissionsRequest
        {
            ServiceName = "test-service",
            Permissions = new List<PermissionDto>
            {
                new() { PermissionId = "different-service.read", Description = "Test" }
            }
        };

        var result = await service.RegisterPermissionsAsync(request);

        Assert.Empty(result);
    }
}
