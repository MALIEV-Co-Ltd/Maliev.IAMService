using Maliev.Aspire.ServiceDefaults.IAM;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Services;
using Maliev.IAMService.Data;
using Maliev.IAMService.Tests.Testing;
using Maliev.MessagingContracts.Generated;
using MassTransit;
using MassTransit.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Integration tests for PermissionRegistrationRequestConsumer.
/// Tests the RabbitMQ-based IAM registration flow introduced after migration from HTTP-based registration.
/// </summary>
public class PermissionRegistrationRequestConsumerTests : BaseIntegrationTest
{
    public PermissionRegistrationRequestConsumerTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task ConsumeMessage_ValidPermissionsAndRoles_RegistersSuccessfully()
    {
        await CleanDatabaseAsync();

        // Arrange
        var harness = Factory.Services.GetRequiredService<ITestHarness>();
        var serviceName = "test-service";

        var message = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = serviceName,
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>
            {
                new() { PermissionId = $"{serviceName}.data.read", Description = "Read data" },
                new() { PermissionId = $"{serviceName}.data.write", Description = "Write data" },
                new() { PermissionId = $"{serviceName}.data.delete", Description = "Delete data" }
            },
            Roles = new List<PermissionRegistrationRequestRolesItem>
            {
                new()
                {
                    RoleId = $"roles.{serviceName}.admin",
                    Description = "Admin role",
                    PermissionIds = new List<string>
                    {
                        $"{serviceName}.data.read",
                        $"{serviceName}.data.write",
                        $"{serviceName}.data.delete"
                    }
                },
                new()
                {
                    RoleId = $"roles.{serviceName}.viewer",
                    Description = "Viewer role",
                    PermissionIds = new List<string> { $"{serviceName}.data.read" }
                }
            }
        };

        // Act
        await harness.Bus.Publish(message);

        // Wait for consumer to process
        await Task.Delay(1000);

        // Assert - Verify permissions were registered
        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();

        var registeredPermissions = await dbContext.Permissions
            .Where(p => p.PermissionId.StartsWith(serviceName))
            .ToListAsync();

        Assert.Equal(3, registeredPermissions.Count);
        Assert.Contains(registeredPermissions, p => p.PermissionId == $"{serviceName}.data.read");
        Assert.Contains(registeredPermissions, p => p.PermissionId == $"{serviceName}.data.write");
        Assert.Contains(registeredPermissions, p => p.PermissionId == $"{serviceName}.data.delete");

        // Assert - Verify roles were registered
        var registeredRoles = await dbContext.Roles
            .Include(r => r.RolePermissions)
            .Where(r => r.RoleId.StartsWith($"roles.{serviceName}"))
            .ToListAsync();

        Assert.Equal(2, registeredRoles.Count);

        var adminRole = registeredRoles.First(r => r.RoleId == $"roles.{serviceName}.admin");
        Assert.Equal(3, adminRole.RolePermissions.Count);

        var viewerRole = registeredRoles.First(r => r.RoleId == $"roles.{serviceName}.viewer");
        Assert.Single(viewerRole.RolePermissions);
    }

    [Fact]
    public async Task ConsumeMessage_PermissionsOnly_RegistersWithoutRoles()
    {
        await CleanDatabaseAsync();

        // Arrange
        var harness = Factory.Services.GetRequiredService<ITestHarness>();
        var serviceName = "permissions-only-service";

        var message = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = serviceName,
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>
            {
                new() { PermissionId = $"{serviceName}.action.execute", Description = "Execute action" }
            },
            Roles = new List<PermissionRegistrationRequestRolesItem>() // Empty roles
        };

        // Act
        await harness.Bus.Publish(message);
        await Task.Delay(1000);

        // Assert
        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();

        var registeredPermissions = await dbContext.Permissions
            .Where(p => p.PermissionId.StartsWith(serviceName))
            .ToListAsync();

        Assert.Single(registeredPermissions);
        Assert.Equal($"{serviceName}.action.execute", registeredPermissions[0].PermissionId);

        // No roles should be registered
        var registeredRoles = await dbContext.Roles
            .Where(r => r.RoleId.StartsWith($"roles.{serviceName}"))
            .ToListAsync();

        Assert.Empty(registeredRoles);
    }

    [Fact]
    public async Task ConsumeMessage_RolesOnly_RegistersWithoutPermissions()
    {
        await CleanDatabaseAsync();

        // Arrange - First register some permissions manually
        var serviceName = "roles-only-service";
        using (var scope = Factory.Services.CreateScope())
        {
            var permissionService = scope.ServiceProvider.GetRequiredService<IPermissionService>();
            await permissionService.RegisterPermissionsAsync(new RegisterPermissionsRequest
            {
                ServiceName = serviceName,
                Permissions = new List<PermissionDto>
                {
                    new() { PermissionId = $"{serviceName}.existing.permission", Description = "Existing" }
                }
            });
        }

        var harness = Factory.Services.GetRequiredService<ITestHarness>();

        var message = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = serviceName,
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>(), // Empty permissions
            Roles = new List<PermissionRegistrationRequestRolesItem>
            {
                new()
                {
                    RoleId = $"roles.{serviceName}.user",
                    Description = "User role",
                    PermissionIds = new List<string> { $"{serviceName}.existing.permission" }
                }
            }
        };

        // Act
        await harness.Bus.Publish(message);
        await Task.Delay(1000);

        // Assert
        using var scope2 = Factory.Services.CreateScope();
        var dbContext = scope2.ServiceProvider.GetRequiredService<IAMDbContext>();

        var registeredRoles = await dbContext.Roles
            .Include(r => r.RolePermissions)
            .Where(r => r.RoleId == $"roles.{serviceName}.user")
            .ToListAsync();

        Assert.Single(registeredRoles);
        Assert.Single(registeredRoles[0].RolePermissions);
    }

    [Fact]
    public async Task ConsumeMessage_InvalidPermissionFormat_SkipsInvalidPermissions()
    {
        await CleanDatabaseAsync();

        // Arrange
        var harness = Factory.Services.GetRequiredService<ITestHarness>();
        var serviceName = "invalid-format-service";

        var message = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = serviceName,
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>
            {
                new() { PermissionId = $"{serviceName}.valid.permission", Description = "Valid" },
                new() { PermissionId = "invalid-format", Description = "Missing dots" }, // Invalid
                new() { PermissionId = "x.y", Description = "Only 2 parts" } // Invalid
            },
            Roles = new List<PermissionRegistrationRequestRolesItem>()
        };

        // Act
        await harness.Bus.Publish(message);
        await Task.Delay(1000);

        // Assert - Only valid permission should be registered
        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();

        var registeredPermissions = await dbContext.Permissions
            .Where(p => p.PermissionId.StartsWith(serviceName) || p.PermissionId == "invalid-format" || p.PermissionId == "x.y")
            .ToListAsync();

        Assert.Single(registeredPermissions);
        Assert.Equal($"{serviceName}.valid.permission", registeredPermissions[0].PermissionId);
    }

    [Fact]
    public async Task ConsumeMessage_DuplicateRegistration_UpdatesExisting()
    {
        await CleanDatabaseAsync();

        // Arrange
        var harness = Factory.Services.GetRequiredService<ITestHarness>();
        var serviceName = "duplicate-service";

        var message1 = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = serviceName,
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>
            {
                new() { PermissionId = $"{serviceName}.data.action", Description = "Original description" }
            },
            Roles = new List<PermissionRegistrationRequestRolesItem>()
        };

        var message2 = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = serviceName,
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>
            {
                new() { PermissionId = $"{serviceName}.data.action", Description = "Updated description" }
            },
            Roles = new List<PermissionRegistrationRequestRolesItem>()
        };

        // Act - Register twice
        await harness.Bus.Publish(message1);
        await Task.Delay(500);
        await harness.Bus.Publish(message2);
        await Task.Delay(500);

        // Assert - Should have only one permission with updated description
        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();

        var registeredPermissions = await dbContext.Permissions
            .Where(p => p.PermissionId == $"{serviceName}.data.action")
            .ToListAsync();

        Assert.Single(registeredPermissions);
        Assert.Equal("Updated description", registeredPermissions[0].Description);
    }

    [Fact]
    public async Task ConsumeMessage_RoleWithNonExistentPermissions_SkipsRole()
    {
        await CleanDatabaseAsync();

        // Arrange
        var harness = Factory.Services.GetRequiredService<ITestHarness>();
        var serviceName = "missing-perm-service";

        var message = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = serviceName,
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>(), // No permissions registered
            Roles = new List<PermissionRegistrationRequestRolesItem>
            {
                new()
                {
                    RoleId = $"roles.{serviceName}.admin",
                    Description = "Admin role",
                    PermissionIds = new List<string> { $"{serviceName}.nonexistent.permission" } // Doesn't exist
                }
            }
        };

        // Act
        await harness.Bus.Publish(message);
        await Task.Delay(1000);

        // Assert - Role should not be registered
        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();

        var registeredRoles = await dbContext.Roles
            .Where(r => r.RoleId == $"roles.{serviceName}.admin")
            .ToListAsync();

        Assert.Empty(registeredRoles);
    }

    [Fact]
    public async Task ConsumeMessage_MultipleServices_RegistersSeparately()
    {
        await CleanDatabaseAsync();

        // Arrange
        var harness = Factory.Services.GetRequiredService<ITestHarness>();

        var message1 = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = "service-a",
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>
            {
                new() { PermissionId = "service-a.data.action", Description = "Service A action" }
            },
            Roles = new List<PermissionRegistrationRequestRolesItem>()
        };

        var message2 = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = "service-b",
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>
            {
                new() { PermissionId = "service-b.data.action", Description = "Service B action" }
            },
            Roles = new List<PermissionRegistrationRequestRolesItem>()
        };

        // Act
        await harness.Bus.Publish(message1);
        await harness.Bus.Publish(message2);
        await Task.Delay(1000);

        // Assert
        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();

        var serviceAPermissions = await dbContext.Permissions
            .Where(p => p.PermissionId.StartsWith("service-a"))
            .ToListAsync();

        var serviceBPermissions = await dbContext.Permissions
            .Where(p => p.PermissionId.StartsWith("service-b"))
            .ToListAsync();

        Assert.Single(serviceAPermissions);
        Assert.Single(serviceBPermissions);
    }

    [Fact]
    public async Task ConsumeMessage_ConcurrentRegistration_NoDuplicateKeyErrors()
    {
        await CleanDatabaseAsync();

        var harness = Factory.Services.GetRequiredService<ITestHarness>();
        var serviceName = "concurrent-test";

        var message = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = serviceName,
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>
            {
                new() { PermissionId = $"{serviceName}.data.read", Description = "Read data" },
                new() { PermissionId = $"{serviceName}.data.write", Description = "Write data" }
            },
            Roles = new List<PermissionRegistrationRequestRolesItem>()
        };

        // Act - Publish same message concurrently (simulating race condition)
        var task1 = harness.Bus.Publish(message);
        var task2 = harness.Bus.Publish(message);
        var task3 = harness.Bus.Publish(message);
        await Task.WhenAll(task1, task2, task3);
        await Task.Delay(3000); // Wait for all consumers to process

        // Assert - No duplicate key errors, role should have exactly one instance of each permission
        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();

        var ownerRole = await dbContext.Roles
            .Include(r => r.RolePermissions)
            .FirstOrDefaultAsync(r => r.RoleId == "roles.platform.owner");

        Assert.NotNull(ownerRole);

        // Verify permissions exist exactly once
        var readPermCount = ownerRole.RolePermissions.Count(rp => rp.PermissionId == $"{serviceName}.data.read");
        var writePermCount = ownerRole.RolePermissions.Count(rp => rp.PermissionId == $"{serviceName}.data.write");
        Assert.Equal(1, readPermCount);
        Assert.Equal(1, writePermCount);

        // Verify permissions were registered
        var registeredPermissions = await dbContext.Permissions
            .Where(p => p.PermissionId.StartsWith(serviceName))
            .ToListAsync();
        Assert.Equal(2, registeredPermissions.Count);
    }

    [Fact]
    public async Task ConsumeMessage_UpdatesPlatformOwnerRole_WithNewPermissions()
    {
        await CleanDatabaseAsync();

        var harness = Factory.Services.GetRequiredService<ITestHarness>();
        var serviceName = "owner-role-test";

        var message = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = serviceName,
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>
            {
                new() { PermissionId = $"{serviceName}.special.action", Description = "Special action" }
            },
            Roles = new List<PermissionRegistrationRequestRolesItem>()
        };

        // Act
        await harness.Bus.Publish(message);
        await Task.Delay(1500);

        // Assert - Platform owner role should have the new permission
        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();

        var ownerRole = await dbContext.Roles
            .Include(r => r.RolePermissions)
            .FirstOrDefaultAsync(r => r.RoleId == "roles.platform.owner");

        Assert.NotNull(ownerRole);
        Assert.Contains(ownerRole.RolePermissions, rp => rp.PermissionId == $"{serviceName}.special.action");
    }

    [Fact]
    public async Task ConsumeMessage_ExistingPermissionOnOwnerRole_NotDuplicated()
    {
        await CleanDatabaseAsync();

        var harness = Factory.Services.GetRequiredService<ITestHarness>();
        var serviceName = "no-duplicate-test";

        var message = new PermissionRegistrationRequest
        {
            MessageId = Guid.NewGuid(),
            MessageName = nameof(PermissionRegistrationRequest),
            MessageType = MessageType.Request,
            MessageVersion = "1.0.0",
            PublishedBy = "test",
            ConsumedBy = new List<string> { "iam" },
            CorrelationId = Guid.NewGuid(),
            ServiceName = serviceName,
            Permissions = new List<PermissionRegistrationRequestPermissionsItem>
            {
                new() { PermissionId = $"{serviceName}.unique.action", Description = "Unique action" }
            },
            Roles = new List<PermissionRegistrationRequestRolesItem>()
        };

        // Act - Publish same message twice sequentially
        await harness.Bus.Publish(message);
        await Task.Delay(1000);
        await harness.Bus.Publish(message);
        await Task.Delay(1000);

        // Assert - Owner role should have exactly one instance of the permission
        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();

        var ownerRole = await dbContext.Roles
            .Include(r => r.RolePermissions)
            .FirstOrDefaultAsync(r => r.RoleId == "roles.platform.owner");

        Assert.NotNull(ownerRole);

        var permCount = ownerRole.RolePermissions.Count(rp => rp.PermissionId == $"{serviceName}.unique.action");
        Assert.Equal(1, permCount);
    }
}
