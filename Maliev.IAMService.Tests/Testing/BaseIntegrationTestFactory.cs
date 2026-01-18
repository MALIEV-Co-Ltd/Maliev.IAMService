using System.IdentityModel.Tokens.Jwt;
using System.Diagnostics.CodeAnalysis;
using MassTransit;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Testcontainers.PostgreSql;
using Testcontainers.RabbitMq;
using Testcontainers.Redis;
using Xunit;

// Disable parallel execution to prevent race conditions on the shared singleton database
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Maliev.IAMService.Tests.Testing;

/// <summary>
/// Base integration test factory for IAM Service.
/// Provides PostgreSQL, Redis, and RabbitMQ containers with parallel startup.
/// </summary>
/// <typeparam name="TProgram">The Program class of the service being tested</typeparam>
/// <typeparam name="TDbContext">The DbContext type for the service</typeparam>
public class BaseIntegrationTestFactory<TProgram, TDbContext> : WebApplicationFactory<TProgram>, IAsyncLifetime
    where TProgram : class
    where TDbContext : DbContext
{
    private static PostgreSqlContainer? _postgresContainer;
    private static RedisContainer? _redisContainer;
    private static RabbitMqContainer? _rabbitmqContainer;
    private static bool _containersStarted;
    private static readonly SemaphoreSlim _initLock = new(1, 1);

    private readonly RSA _testRsa;

    /// <summary>
    /// Override this property if your DbContext connection string has a different name.
    /// Defaults to the DbContext class name.
    /// </summary>
    protected virtual string DbConnectionStringName => typeof(TDbContext).Name;

    public BaseIntegrationTestFactory()
    {
        _testRsa = RSA.Create(2048);

        // Set environment variable EARLY so Program.cs picks it up during WebApplication.CreateBuilder
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Testing");
    }

    public async Task InitializeAsync()
    {
        await _initLock.WaitAsync();
        try
        {
            if (!_containersStarted)
            {
                _postgresContainer = new PostgreSqlBuilder()
                    .WithImage("postgres:18-alpine")
                    .Build();

                _redisContainer = new RedisBuilder()
                    .WithImage("redis:8.4-alpine")
                    .Build();

                _rabbitmqContainer = new RabbitMqBuilder()
                    .WithImage("rabbitmq:4.2-alpine")
                    .Build();

                // Start all containers in parallel
                await Task.WhenAll(
                    _postgresContainer.StartAsync(),
                    _redisContainer.StartAsync(),
                    _rabbitmqContainer.StartAsync()
                );

                // Ensure PostgreSQL is fully ready and accepting connections
                var postgresReady = false;
                var retryCount = 0;
                const int maxRetries = 60;
                while (!postgresReady && retryCount < maxRetries)
                {
                    try
                    {
                        await using var conn = new Npgsql.NpgsqlConnection(_postgresContainer.GetConnectionString());
                        await conn.OpenAsync();
                        await using var cmd = conn.CreateCommand();
                        cmd.CommandText = "SELECT 1";
                        await cmd.ExecuteScalarAsync();
                        postgresReady = true;
                    }
                    catch
                    {
                        retryCount++;
                        await Task.Delay(1000);
                    }
                }

                if (!postgresReady)
                {
                    throw new InvalidOperationException("PostgreSQL Testcontainer failed to become ready (Ping failed) after 60 seconds.");
                }

                // Wait for Redis to be ready
                using (var connection = await StackExchange.Redis.ConnectionMultiplexer.ConnectAsync(_redisContainer.GetConnectionString()))
                {
                    await connection.GetDatabase().PingAsync();
                }

                // Apply database migrations
                await ApplyMigrationsAsync();

                _containersStarted = true;
            }
        }
        finally
        {
            _initLock.Release();
        }

        // Set environment variables immediately after containers start
        Environment.SetEnvironmentVariable($"ConnectionStrings__{DbConnectionStringName}", _postgresContainer!.GetConnectionString());
        Environment.SetEnvironmentVariable("ConnectionStrings__redis", _redisContainer!.GetConnectionString());
        Environment.SetEnvironmentVariable("ConnectionStrings__rabbitmq", _rabbitmqContainer!.GetConnectionString());
    }

    public new async Task DisposeAsync()
    {
        // Try to stop MassTransit gracefully before disposing the provider
        if (Services != null)
        {
            try
            {
                var busControl = Services.GetRequiredService<IBusControl>();
                await busControl.StopAsync(new CancellationTokenSource(TimeSpan.FromSeconds(5)).Token);
            }
            catch (Exception)
            {
                // Ignore errors during bus stop in tests
            }
        }

        // Dispose the application FIRST to allow MassTransit to shut down gracefully
        await base.DisposeAsync();

        // Give MassTransit extra time to fully shut down before disposing RabbitMQ container
        await Task.Delay(500);

        // Static containers are NOT disposed here to allow reuse across tests
        _testRsa.Dispose();
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", null); // Cleanup
    }


    protected override IHost CreateHost(IHostBuilder builder)
    {
        // Ensure containers are started before creating host
        if (!_containersStarted)
        {
            InitializeAsync().GetAwaiter().GetResult();
        }

        // Export RSA public key for JWT validation
        var rsaParams = _testRsa.ExportParameters(false);
        Environment.SetEnvironmentVariable("JWT_PUBLIC_KEY_MODULUS", Convert.ToBase64String(rsaParams.Modulus!));
        Environment.SetEnvironmentVariable("JWT_PUBLIC_KEY_EXPONENT", Convert.ToBase64String(rsaParams.Exponent!));

        // Allow derived classes to set additional environment variables
        ConfigureEnvironmentVariables();

        return base.CreateHost(builder);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
            // Optional: add a simple console logger for debugging tests if needed
            // logging.AddConsole();
        });

        builder.ConfigureAppConfiguration((context, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SecurityKey"] = "test-secret-key-at-least-32-characters-long",
                [$"ConnectionStrings:{DbConnectionStringName}"] = _postgresContainer!.GetConnectionString(),
                ["ConnectionStrings:redis"] = _redisContainer!.GetConnectionString(),
                ["ConnectionStrings:rabbitmq"] = _rabbitmqContainer!.GetConnectionString()
            });
        });

        builder.ConfigureTestServices(services =>
        {
            // Configure JWT Bearer authentication with test RSA key
            services.PostConfigureAll<Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions>(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = "test-issuer",
                    ValidAudience = "test-audience",
                    IssuerSigningKey = new RsaSecurityKey(_testRsa),
                    ClockSkew = TimeSpan.Zero, // No clock skew for tests
                    NameClaimType = "sub",
                    RoleClaimType = "role"
                };
            });

            // Add MassTransit test harness for testing message publishing/consuming
            services.AddMassTransitTestHarness();

            // Allow derived classes to add additional test services
            ConfigureAdditionalServices(services);
        });
    }

    /// <summary>
    /// Override this method to set additional environment variables before host creation.
    /// Called after standard environment variables are set.
    /// </summary>
    protected virtual void ConfigureEnvironmentVariables()
    {
        // Override in derived class if needed
    }

    /// <summary>
    /// Override this method to add additional test services to the DI container.
    /// </summary>
    protected virtual void ConfigureAdditionalServices(IServiceCollection services)
    {
        // Override in derived class if needed
    }

    /// <summary>
    /// Gets the DbContext from the service provider for use in tests.
    /// </summary>
    public TDbContext GetDbContext()
    {
        var scope = Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<TDbContext>();
    }

    /// <summary>
    /// Creates a new DbContext instance for testing (not from DI container).
    /// </summary>
    public TDbContext CreateDbContext()
    {
        var connectionString = _postgresContainer!.GetConnectionString();
        var optionsBuilder = new DbContextOptionsBuilder<TDbContext>();
        optionsBuilder.UseNpgsql(connectionString);
        return (TDbContext)Activator.CreateInstance(typeof(TDbContext), optionsBuilder.Options)!;
    }

    /// <summary>
    /// Applies all pending migrations to the test database.
    /// </summary>
    private async Task ApplyMigrationsAsync()
    {
        await using var context = CreateDbContext();
        await context.Database.MigrateAsync();
    }

    /// <summary>
    /// Cleans all data from the database while preserving schema.
    /// Queries the database schema dynamically to get all tables.
    /// </summary>
    [SuppressMessage("Security", "EF1002:Gaps in SQL queries", Justification = "Table names are retrieved from information_schema and are safe.")]
    public async Task CleanDatabaseAsync()
    {
        // Explicitly close any existing connections and clear the pool
        Npgsql.NpgsqlConnection.ClearAllPools();

        await using var context = CreateDbContext();

        // Get all table names from information_schema
        var tableNames = await context.Database
            .SqlQueryRaw<string>(
                @"SELECT table_name
                  FROM information_schema.tables
                  WHERE table_schema = 'public'
                  AND table_type = 'BASE TABLE'
                  AND table_name != '__EFMigrationsHistory'
                  ORDER BY table_name")
            .ToListAsync();

        // Truncate all tables (CASCADE handles foreign keys)
        foreach (var tableName in tableNames)
        {
            try
            {
                await context.Database.ExecuteSqlRawAsync($"TRUNCATE TABLE \"{tableName}\" RESTART IDENTITY CASCADE");
            }
            catch (Npgsql.PostgresException ex) when (ex.SqlState == "42P01")
            {
                // Table doesn't exist - ignore this error
            }
        }

        // Explicitly close the connection after cleanup
        await context.Database.CloseConnectionAsync();
    }

    /// <summary>
    /// Alias for CleanDatabaseAsync to support different naming conventions.
    /// </summary>
    public Task ResetDatabaseAsync() => CleanDatabaseAsync();

    /// <summary>
    /// Creates a test JWT token for authentication in integration tests.
    /// </summary>
    /// <param name="userId">User ID to include in token</param>
    /// <param name="roles">Roles to include in token claims</param>
    /// <param name="permissions">Permissions to include in token claims (multi-value)</param>
    /// <param name="additionalClaims">Additional claims to include</param>
    /// <returns>JWT token string</returns>
    public string CreateTestJwtToken(
        string userId = "test-user",
        string[]? roles = null,
        string[]? permissions = null,
        Dictionary<string, string>? additionalClaims = null)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        if (roles != null)
        {
            foreach (var role in roles)
            {
                claims.Add(new Claim("role", role));
            }
        }

        if (permissions != null)
        {
            foreach (var permission in permissions)
            {
                claims.Add(new Claim("permissions", permission));
            }
        }

        if (additionalClaims != null)
        {
            foreach (var (key, value) in additionalClaims)
            {
                claims.Add(new Claim(key, value));
            }
        }

        var rsaSecurityKey = new RsaSecurityKey(_testRsa);
        var signingCredentials = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);

        var token = new JwtSecurityToken(
            issuer: "test-issuer",
            audience: "test-audience",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: signingCredentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Creates an HTTP client with authenticated user and specified roles.
    /// </summary>
    public HttpClient CreateAuthenticatedClient(string userId = "test-user", string[]? roles = null)
    {
        var token = CreateTestJwtToken(userId, roles);
        var client = CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        return client;
    }

    /// <summary>
    /// Creates an HTTP client authenticated as a service account for IAM registration endpoints.
    /// </summary>
    public HttpClient CreateServiceAccountClient(string serviceAccountId = "test-service-account")
    {
        var additionalClaims = new Dictionary<string, string>
        {
            ["principal_type"] = "service_account"
        };

        var token = CreateTestJwtToken(
            userId: serviceAccountId,
            roles: new[] { "service-account" },
            additionalClaims: additionalClaims);

        var client = CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        return client;
    }
}
