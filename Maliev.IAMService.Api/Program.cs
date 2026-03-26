using Maliev.Aspire.ServiceDefaults;
using Maliev.IAMService.Api.Health;
using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Application.Services;
using Maliev.IAMService.Infrastructure.Persistence;
using Maliev.IAMService.Infrastructure.Repositories;
using Maliev.Aspire.ServiceDefaults.IAM;
using Microsoft.EntityFrameworkCore;

// Initialize bootstrap logging
using var loggerFactory = LoggerFactory.Create(logBuilder => logBuilder.AddConsole());
var bootstrapLogger = loggerFactory.CreateLogger("Program");

try
{
    Program.Log.StartingHost(bootstrapLogger, "IAM Service");

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

    // ===== IAM Infrastructure Seeder (runs early, seeds system principal, roles, etc.) =====
    builder.Services.AddHostedService<IAMInfrastructureSeederHostedService>();

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
    builder.AddStandardCache("iam:"); // Redis + in-memory fallback, memory-optimized
    builder.Services.AddScoped<ICacheService, CacheService>();

    // ===== RabbitMQ with MassTransit =====
    builder.AddMassTransitWithRabbitMq(x =>
    {
        // Register event consumers
        x.AddConsumer<Maliev.IAMService.Api.Events.PrincipalRoleGrantedEventConsumer>();
        x.AddConsumer<Maliev.IAMService.Api.Events.PrincipalRoleRevokedEventConsumer>();
        x.AddConsumer<Maliev.IAMService.Api.Events.RoleUpdatedEventConsumer>();
        x.AddConsumer<Maliev.IAMService.Api.Consumers.PermissionRegistrationRequestConsumer>();
        x.AddConsumer<Maliev.IAMService.Api.Consumers.EmployeeCreatedConsumer>();
    });

    // ===== IAM Registration =====
    builder.Services.AddIAMRegistration<IAMIAMRegistrationService>("iam");

    // --- API Configuration ---
    builder.AddStandardCors(); // CORS with fail-fast validation
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

    // ===== Rate Limiting (memory-optimized for low-spec nodes) =====
    // Note: IAM Service uses standard rate limiting. Custom policies can be added via middleware if needed.
    builder.AddStandardRateLimiting();

    var app = builder.Build();
    var logger = app.Services.GetRequiredService<ILogger<Program>>();

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

    // Run migrations on startup (except in Testing environment where factory handles it)
    if (!app.Environment.IsEnvironment("Testing"))
    {
        await app.MigrateDatabaseAsync<IAMDbContext>();
        initTracker.MarkDatabaseMigrationsComplete();
    }
    else
    {
        initTracker.MarkDatabaseMigrationsComplete();
    }


    // ===== Authentication & Authorization =====
    app.UseAuthentication();
    app.UseAuthorization();

    // ===== Controller Routes =====
    app.MapControllers();


    Program.Log.ServiceStarted(logger, "IAM Service");
    app.Run();
}
catch (Exception ex)
{
    Program.Log.HostTerminated(bootstrapLogger, ex, "IAM Service");
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
public partial class Program
{
    internal static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information, Message = "Starting {ServiceName} host")]
        public static partial void StartingHost(ILogger logger, string serviceName);

        [LoggerMessage(Level = LogLevel.Critical, Message = "{ServiceName} host terminated unexpectedly during startup")]
        public static partial void HostTerminated(ILogger logger, Exception ex, string serviceName);

        [LoggerMessage(Level = LogLevel.Information, Message = "{ServiceName} started successfully")]
        public static partial void ServiceStarted(ILogger logger, string serviceName);
    }
}
