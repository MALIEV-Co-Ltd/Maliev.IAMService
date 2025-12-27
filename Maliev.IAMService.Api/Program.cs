using Maliev.IAMService.Data;
using Maliev.IAMService.Data.Repositories;
using Maliev.IAMService.Api.Services;
using Maliev.IAMService.Api.Health;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using MassTransit;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Scalar.AspNetCore;
using Maliev.Aspire.ServiceDefaults;


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

// ===== Database Configuration =====
builder.AddPostgresDbContext<IAMDbContext>("IAMDatabase");

// ===== Repository Layer Registration =====
builder.Services.AddScoped<IPrincipalRepository, PrincipalRepository>();
builder.Services.AddScoped<IPermissionRepository, PermissionRepository>();
builder.Services.AddScoped<IRoleRepository, RoleRepository>();
builder.Services.AddScoped<IBindingRepository, BindingRepository>();
builder.Services.AddScoped<IAuditRepository, AuditRepository>();
builder.Services.AddScoped<IServiceAccountApiKeyRepository, ServiceAccountApiKeyRepository>();

// ===== Infrastructure Services =====
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
});

// --- API Configuration ---
builder.AddDefaultCors(); // CORS from CORS:AllowedOrigins config
builder.AddDefaultApiVersioning(); // API versioning with URL segment reader

// ===== JWT Authentication =====
var jwtPrivateKey = builder.Configuration["Jwt:PrivateKey"];
var jwtPublicKey = builder.Configuration["Jwt:PublicKey"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "Maliev.IAMService";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "Maliev.Services";

RSA? rsaPrivate = null;
if (!string.IsNullOrEmpty(jwtPrivateKey))
{
    try
    {
        rsaPrivate = RSA.Create();
        rsaPrivate.ImportRSAPrivateKey(Convert.FromBase64String(jwtPrivateKey), out _);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Warning: Failed to load Jwt:PrivateKey: {ex.Message}");
    }
}

RSA? rsaPublic = null;
if (!string.IsNullOrEmpty(jwtPublicKey))
{
    try
    {
        rsaPublic = RSA.Create();
        // Handle both PEM and simple Base64 if needed, but standardizing on PEM as per ServiceDefaults
        var publicKeyPem = Encoding.UTF8.GetString(Convert.FromBase64String(jwtPublicKey));
        rsaPublic.ImportFromPem(publicKeyPem);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Warning: Failed to load Jwt:PublicKey: {ex.Message}");
    }
}

// Add service account authentication handler
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = rsaPublic != null,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = rsaPublic != null ? new RsaSecurityKey(rsaPublic) : null,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        // In development, if no public key is provided, allow any signature to prevent startup crash
        if (builder.Environment.IsDevelopment() && rsaPublic == null)
        {
            options.TokenValidationParameters.SignatureValidator = delegate (string token, TokenValidationParameters parameters)
            {
                var handler = new JwtSecurityTokenHandler();
                return handler.ReadJwtToken(token);
            };
        }
    })
    .AddScheme<Maliev.IAMService.Api.Authorization.ServiceAccountAuthOptions,
               Maliev.IAMService.Api.Authorization.ServiceAccountAuthHandler>(
        "ServiceAccount", options => { });

builder.Services.AddAuthorization();

// ===== OpenAPI with Scalar UI =====
builder.AddStandardOpenApi(
    title: "MALIEV IAM Service API",
    description: "Centralized Identity and Access Management service. Manages principals, permissions, and roles across the entire platform.");

// ===== Controllers =====
builder.Services.AddControllers();

// ===== Rate Limiting (10 requests per minute for token endpoints) =====
builder.Services.AddRateLimiter(options =>
{
    // Custom policy for registration (more lenient)
    options.AddPolicy("registration_limit", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: "registration",
            factory: partition => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
            {
                PermitLimit = 100, // Allow burst during startup
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
                QueueLimit = 50
            }));

    // Custom policy for token endpoints (stricter)
    options.AddPolicy("token_limit", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: "token_limit",
            factory: partition => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        // Exempt registration and health checks from global limiting
        var path = httpContext.Request.Path.Value ?? string.Empty;
        if (path.Contains("/register") || path.Contains("/liveness") || path.Contains("/readiness"))
        {
            return RateLimitPartition.GetNoLimiter("no_limit");
        }

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: "global_limit",
            factory: partition => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
                QueueLimit = 10
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

app.UseHttpsRedirection();

// ===== Rate Limiting =====
app.UseRateLimiter();

// Run migrations on startup
try
{
    await app.MigrateDatabaseAsync<IAMDbContext>();
    initTracker.MarkDatabaseMigrationsComplete();
}
catch (Exception ex)
{
    Console.WriteLine($"Error applying migrations: {ex.Message}");
}

// ===== Authentication & Authorization =====
app.UseAuthentication();
app.UseAuthorization();

// ===== Controller Routes =====
app.MapControllers();

// Mark initialization complete before app.Run()
// By the time app.Run() is called, hosted services (including MassTransit) are configured
// and will be started by the host. We mark them as "will be ready" so the health check
// reports healthy once Kestrel starts listening.
initTracker.MarkMassTransitStarted();
initTracker.MarkApiReady();

app.Run();

// Make Program class public for integration tests
public partial class Program { }
