#pragma warning disable CA1848 // For improved performance, use the LoggerMessage delegates
using Maliev.IAMService.Data;
using Maliev.IAMService.Data.Repositories;
using Maliev.IAMService.Api.Services;
using Maliev.IAMService.Api.Health;
using MassTransit;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Maliev.Aspire.ServiceDefaults;
using Microsoft.Extensions.Logging;

// Initialize bootstrap logging
using var loggerFactory = LoggerFactory.Create(logBuilder => logBuilder.AddConsole());
var bootstrapLogger = loggerFactory.CreateLogger("Program");

try
{
    bootstrapLogger.LogInformation("Starting IAM Service host");

    var builder = WebApplication.CreateBuilder(args);

    // ===== Initialization Tracker =====
    var initTracker = new IAMInitializationTracker();
    builder.Services.AddSingleton(initTracker);

    // ===== Service Defaults (OpenTelemetry, Health Checks, Service Discovery) =====
    builder.AddServiceDefaults();
    builder.AddServiceMeters("iam-service");

    // ===== Custom IAM Readiness Health Check =====
    builder.Services.AddHealthChecks()
        .AddCheck<IAMReadinessHealthCheck>("iam_ready", tags: new[] { "ready" });

    // ===== IAM Initialization Hosted Service =====
    builder.Services.AddHostedService<IAMInitializationHostedService>();

    // ===== Database Configuration =====
    builder.AddPostgresDbContext<IAMDbContext>("IamDbContext");

    // ===== Repository Layer Registration =====
    builder.Services.AddScoped<IPrincipalRepository, PrincipalRepository>();
    builder.Services.AddScoped<IPermissionRepository, PermissionRepository>();
    builder.Services.AddScoped<IRoleRepository, RoleRepository>();
    builder.Services.AddScoped<IBindingRepository, BindingRepository>();
    builder.Services.AddScoped<IAuditRepository, AuditRepository>();
    builder.Services.AddScoped<IServiceAccountApiKeyRepository, ServiceAccountApiKeyRepository>();

    // ===== Infrastructure Services =====
    // RSA key provider as Singleton to ensure consistent JWT signing key across all requests
    builder.Services.AddSingleton<IRsaKeyProvider, RsaKeyProvider>();
    builder.Services.AddScoped<IPrincipalService, PrincipalService>();
    builder.Services.AddScoped<IAuditService, AuditService>();
    builder.Services.AddScoped<IPermissionService, PermissionService>();
    builder.Services.AddScoped<IRoleService, RoleService>();
    builder.Services.AddScoped<IBindingService, BindingService>();
    builder.Services.AddScoped<IPermissionResolver, PermissionResolver>();
    builder.Services.AddScoped<ITokenService, TokenService>();

    // ===== Authorization Infrastructure =====
    builder.Services.AddPermissionAuthorization();

    // ===== Redis Distributed Cache =====
    builder.AddRedisDistributedCache(instanceName: "iam:");
    builder.Services.AddScoped<ICacheService, CacheService>();

    // ===== RabbitMQ with MassTransit =====
    builder.AddMassTransitWithRabbitMq(x =>
    {
        // Register event consumers
        x.AddConsumer<Maliev.IAMService.Api.Events.PrincipalRoleGrantedEventConsumer>();
        x.AddConsumer<Maliev.IAMService.Api.Events.PrincipalRoleRevokedEventConsumer>();
        x.AddConsumer<Maliev.IAMService.Api.Events.RoleUpdatedEventConsumer>();
        x.AddConsumer<Maliev.IAMService.Api.Consumers.PermissionRegistrationRequestConsumer>();
    });

    // --- API Configuration ---
    builder.AddDefaultCors(); // CORS from CORS:AllowedOrigins config
    builder.AddDefaultApiVersioning(); // API versioning with URL segment reader

    // ===== JWT Authentication =====
    // Use ServiceDefaults extension which supports both RSA (user tokens) and HMAC (service account tokens)
    builder.AddJwtAuthentication();

    // Configure default authorization policy
    builder.Services.AddAuthorization(options =>
    {
        options.DefaultPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
    });

    // ===== OpenAPI with Scalar UI =====
    builder.AddStandardOpenApi(
        title: "MALIEV IAM Service API",
        description: "Centralized Identity and Access Management service. Manages principals, permissions, and roles across the entire platform.");

    // ===== Controllers =====
    builder.Services.AddControllers();

    // ===== Rate Limiting =====
    builder.Services.AddRateLimiter(options =>
    {
        // Custom policy for registration (no limit for internal platform traffic)
        options.AddPolicy("registration_limit", httpContext =>
            RateLimitPartition.GetNoLimiter("registration"));

        // Custom policy for token endpoints (stricter)
        options.AddPolicy("token_limit", httpContext =>
            RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: "token_limit",
                factory: partition => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
                {
                    PermitLimit = 100, // Increased for performance
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0
                }));

        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        {
            // Platform internal traffic uses high limits
            if (httpContext.Request.Headers.ContainsKey("X-Service-Name"))
            {
                return RateLimitPartition.GetNoLimiter("platform_internal");
            }

            return RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: "global_limit",
                factory: partition => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
                {
                    PermitLimit = 500, // Relaxed for local dev/testing
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 100
                });
        });
    });

    var app = builder.Build();

    // ===== HTTP Request Pipeline =====
    app.UseStandardMiddleware();
    app.UseCors();

    // Use ServiceDefaults health/metrics endpoints
    app.MapDefaultEndpoints("iam");

    // Map OpenAPI and Scalar documentation (dev/staging only)
    app.MapApiDocumentation(servicePrefix: "iam");

    // HTTPS redirection disabled in Development (Aspire uses HTTP for service-to-service)
    if (!app.Environment.IsDevelopment())
    {
        app.UseHttpsRedirection();
    }

    // ===== Rate Limiting =====
    app.UseRateLimiter();

    // Run migrations on startup
    await app.MigrateDatabaseAsync<IAMDbContext>();
    initTracker.MarkDatabaseMigrationsComplete();

    // ===== Authentication & Authorization =====
    app.UseAuthentication();
    app.UseAuthorization();

    // Seed geometry-service principal for integration tests (Development/Testing only)
    if (app.Environment.IsDevelopment())
    {
        using var scope = app.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IAMDbContext>();
        var serviceName = "geometry-service";
        var email = $"{serviceName}@serviceaccount.maliev.local";

        // 1. Seed the permission first to satisfy FK constraint
        var permissionId = "upload.files.upload";
        if (!await dbContext.Permissions.AnyAsync(p => p.PermissionId == permissionId))
        {
            dbContext.Permissions.Add(new Maliev.IAMService.Data.Entities.Permission
            {
                PermissionId = permissionId,
                ServiceName = "upload",
                ResourceType = "files",
                Action = "upload",
                Description = "Upload files (Seed)",
                RegisteredAt = DateTime.UtcNow
            });
            await dbContext.SaveChangesAsync();
        }

        // 2. Seed the principal
        if (!await dbContext.Principals.AnyAsync(p => p.Email == email))
        {
            var principalId = Guid.NewGuid();
            dbContext.Principals.Add(new Maliev.IAMService.Data.Entities.Principal
            {
                PrincipalId = principalId,
                PrincipalType = "service_account",
                Email = email,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            });

            // 3. Grant upload.files.upload permission via a direct role binding
            var roleId = "roles.system.geometry-service";
            if (!await dbContext.Roles.AnyAsync(r => r.RoleId == roleId))
            {
                var role = new Maliev.IAMService.Data.Entities.Role
                {
                    RoleId = roleId,
                    RoleName = "Geometry Service Role",
                    Description = "System role for geometry service",
                    ServiceName = "system",
                    IsCustom = false,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };
                dbContext.Roles.Add(role);

                dbContext.RolePermissions.Add(new Maliev.IAMService.Data.Entities.RolePermission
                {
                    RoleId = roleId,
                    PermissionId = permissionId,
                    AddedAt = DateTime.UtcNow
                });
            }

            dbContext.PrincipalRoleBindings.Add(new Maliev.IAMService.Data.Entities.PrincipalRoleBinding
            {
                BindingId = Guid.NewGuid(),
                PrincipalId = principalId,
                RoleId = roleId,
                GrantedBy = Guid.Empty,
                GrantedAt = DateTime.UtcNow
            });

            await dbContext.SaveChangesAsync();
        }
    }

    // ===== Controller Routes =====
    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    bootstrapLogger.LogCritical(ex, "IAM Service host terminated unexpectedly during startup");
    throw;
}
finally
{
    loggerFactory.Dispose();
}

/// <summary>
/// Main entry point for the application.
/// Exposed for integration testing.
/// </summary>
public partial class Program { }
