using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Services;
using Maliev.MessagingContracts.Generated;
using MassTransit;

namespace Maliev.IAMService.Api.Consumers;

/// <summary>
/// MassTransit consumer that handles permission registration requests from other services.
/// Processes registration requests asynchronously from RabbitMQ queue.
/// </summary>
public class PermissionRegistrationRequestConsumer : IConsumer<PermissionRegistrationRequest>
{
    private readonly IPermissionService _permissionService;
    private readonly IRoleService _roleService;
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly ILogger<PermissionRegistrationRequestConsumer> _logger;

    /// <summary>
    /// Initializes a new instance of the PermissionRegistrationRequestConsumer.
    /// </summary>
    /// <param name="permissionService">Service for registering permissions.</param>
    /// <param name="roleService">Service for registering roles.</param>
    /// <param name="publishEndpoint">MassTransit endpoint for publishing completion events.</param>
    /// <param name="logger">Logger instance.</param>
    public PermissionRegistrationRequestConsumer(
        IPermissionService permissionService,
        IRoleService roleService,
        IPublishEndpoint publishEndpoint,
        ILogger<PermissionRegistrationRequestConsumer> logger)
    {
        _permissionService = permissionService;
        _roleService = roleService;
        _publishEndpoint = publishEndpoint;
        _logger = logger;
    }

    /// <summary>
    /// Consumes a permission registration request and registers permissions/roles with the IAM service.
    /// </summary>
    /// <param name="context">The consume context containing the message.</param>
    public async Task Consume(ConsumeContext<PermissionRegistrationRequest> context)
    {
        var request = context.Message;
        _logger.LogInformation(
            "Processing IAM registration request for {ServiceName}: {PermissionCount} permissions, {RoleCount} roles",
            request.ServiceName, request.Permissions.Count, request.Roles.Count);

        try
        {
            // Register permissions
            if (request.Permissions.Any())
            {
                var permissionRequest = new RegisterPermissionsRequest
                {
                    ServiceName = request.ServiceName,
                    Permissions = request.Permissions
                        .Select(p => new PermissionDto
                        {
                            PermissionId = p.PermissionId,
                            Description = p.Description ?? string.Empty
                        })
                        .ToList()
                };

                await _permissionService.RegisterPermissionsAsync(permissionRequest, context.CancellationToken);
            }

            // Register roles
            if (request.Roles.Any())
            {
                var roleRequest = new RegisterRolesRequest
                {
                    ServiceName = request.ServiceName,
                    Roles = request.Roles
                        .Select(r => new RoleDto
                        {
                            RoleId = r.RoleId,
                            Description = r.Description ?? string.Empty,
                            PermissionIds = r.PermissionIds.ToList()
                        })
                        .ToList()
                };

                await _roleService.RegisterRolesAsync(roleRequest, context.CancellationToken);
            }

            _logger.LogInformation(
                "Successfully processed IAM registration for {ServiceName}",
                request.ServiceName);

            // Publish completion event for monitoring/debugging
            await _publishEndpoint.Publish(new PermissionRegistrationCompleted(
                MessageId: Guid.NewGuid(),
                MessageName: nameof(PermissionRegistrationCompleted),
                MessageType: MessageType.Event,
                MessageVersion: "1.0.0",
                PublishedBy: "iam",
                ConsumedBy: [],
                CorrelationId: context.CorrelationId ?? Guid.NewGuid(),
                CausationId: context.MessageId,
                OccurredAtUtc: DateTimeOffset.UtcNow,
                IsPublic: false,
                ServiceName: request.ServiceName,
                PermissionCount: request.Permissions.Count,
                RoleCount: request.Roles.Count,
                RegisteredAt: DateTimeOffset.UtcNow
            ), context.CancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to process IAM registration for {ServiceName}", request.ServiceName);
            throw; // Rethrow to trigger MassTransit retry/error handling
        }
    }
}
