using Maliev.IAMService.Infrastructure.Persistence;
using Maliev.IAMService.Tests.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;

namespace Maliev.IAMService.Tests.Integration;

[Collection("Integration Tests")]
public sealed class WorkloadProvisioningMigrationTests(TestWebApplicationFactory factory)
{
    private const string PreHardeningMigration = "20260715224757_AddWorkloadPrincipalProvisioning";

    [Fact]
    public async Task HardeningMigration_BackfillsActorAndAddsRestrictiveForeignKeys()
    {
        var schema = CreateSchemaName();
        await CreateSchemaAsync(schema);
        try
        {
            await using var context = CreateContext(schema);
            var migrator = context.GetService<IMigrator>();
            await migrator.MigrateAsync(PreHardeningMigration);

            var actorId = Guid.NewGuid();
            var workloadPrincipalId = Guid.NewGuid();
            var operationId = Guid.NewGuid();
            await SeedLegacyOperationAsync(context, actorId, workloadPrincipalId, operationId, includeAudit: true);

            await migrator.MigrateAsync();

            var performedBy = await context.Database
                .SqlQuery<Guid>($"SELECT performed_by AS \"Value\" FROM workload_provisioning_operations WHERE operation_id = {operationId}")
                .SingleAsync();
            Assert.Equal(actorId, performedBy);

            var actorDelete = await Assert.ThrowsAsync<PostgresException>(
                () => context.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM principals WHERE principal_id = {actorId}"));
            Assert.Equal(PostgresErrorCodes.RestrictViolation, actorDelete.SqlState);

            var workloadDelete = await Assert.ThrowsAsync<PostgresException>(
                () => context.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM principals WHERE principal_id = {workloadPrincipalId}"));
            Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, workloadDelete.SqlState);
        }
        finally
        {
            await DropSchemaAsync(schema);
        }
    }

    [Fact]
    public async Task HardeningMigration_UnattributableLegacyOperation_FailsClosed()
    {
        var schema = CreateSchemaName();
        await CreateSchemaAsync(schema);
        try
        {
            await using var context = CreateContext(schema);
            var migrator = context.GetService<IMigrator>();
            await migrator.MigrateAsync(PreHardeningMigration);
            await SeedLegacyOperationAsync(
                context,
                Guid.NewGuid(),
                Guid.NewGuid(),
                Guid.NewGuid(),
                includeAudit: false);

            var exception = await Assert.ThrowsAsync<PostgresException>(() => migrator.MigrateAsync());
            Assert.Contains("cannot attribute existing workload provisioning operations", exception.MessageText, StringComparison.Ordinal);
        }
        finally
        {
            await DropSchemaAsync(schema);
        }
    }

    [Theory]
    [InlineData("user", false)]
    [InlineData("service_account", true)]
    public async Task HardeningMigration_InvalidAuditActor_FailsClosed(string principalType, bool isActive)
    {
        var schema = CreateSchemaName();
        await CreateSchemaAsync(schema);
        try
        {
            await using var context = CreateContext(schema);
            var migrator = context.GetService<IMigrator>();
            await migrator.MigrateAsync(PreHardeningMigration);
            await SeedLegacyOperationAsync(
                context,
                Guid.NewGuid(),
                Guid.NewGuid(),
                Guid.NewGuid(),
                includeAudit: true,
                actorPrincipalType: principalType,
                actorIsActive: isActive);

            var exception = await Assert.ThrowsAsync<PostgresException>(() => migrator.MigrateAsync());
            Assert.Contains("cannot attribute existing workload provisioning operations", exception.MessageText, StringComparison.Ordinal);
        }
        finally
        {
            await DropSchemaAsync(schema);
        }
    }

    private IAMDbContext CreateContext(string schema)
    {
        var connectionString = new NpgsqlConnectionStringBuilder(factory.MigrationTestConnectionString)
        {
            SearchPath = schema
        }.ConnectionString;
        var options = new DbContextOptionsBuilder<IAMDbContext>()
            .UseNpgsql(connectionString)
            .Options;
        return new IAMDbContext(options);
    }

    private async Task CreateSchemaAsync(string schema)
    {
        await using var connection = new NpgsqlConnection(factory.MigrationTestConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"CREATE SCHEMA \"{schema}\"";
        await command.ExecuteNonQueryAsync();
    }

    private async Task DropSchemaAsync(string schema)
    {
        await using var connection = new NpgsqlConnection(factory.MigrationTestConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"DROP SCHEMA IF EXISTS \"{schema}\" CASCADE";
        await command.ExecuteNonQueryAsync();
    }

    private static async Task SeedLegacyOperationAsync(
        IAMDbContext context,
        Guid actorId,
        Guid workloadPrincipalId,
        Guid operationId,
        bool includeAudit,
        string actorPrincipalType = "user",
        bool actorIsActive = true)
    {
        var now = DateTime.UtcNow;
        await context.Database.ExecuteSqlInterpolatedAsync(
            $"""
             INSERT INTO principals
                 (principal_id, principal_type, email, display_name, is_active, created_at, updated_at, workload_id)
             VALUES
                 ({actorId}, {actorPrincipalType}, {actorId.ToString("D") + "@example.test"}, 'Legacy actor', {actorIsActive}, {now}, {now}, NULL),
                 ({workloadPrincipalId}, 'service_account', 'auth-service@workload.maliev.local', 'Auth workload', TRUE, {now}, {now}, 'auth-service')
             """);
        await context.Database.ExecuteSqlInterpolatedAsync(
            $"""
             INSERT INTO workload_provisioning_operations
                 (operation_id, workload_id, profile_version, request_hash, principal_id, completed_at)
             VALUES
                 ({operationId}, 'auth-service', 1, {new string('a', 64)}, {workloadPrincipalId}, {now})
             """);

        if (includeAudit)
        {
            await context.Database.ExecuteSqlInterpolatedAsync(
                $"""
                 INSERT INTO iamaudit_logs
                     (log_id, action, principal_id, performed_by, timestamp, details)
                 VALUES
                     ({Guid.NewGuid()}, 'PROVISION_WORKLOAD_PRINCIPAL', {workloadPrincipalId}, {actorId}, {now}, {"operation_id=" + operationId.ToString("D")})
                 """);
        }
    }

    private static string CreateSchemaName() => $"migration_{Guid.NewGuid():N}";
}
