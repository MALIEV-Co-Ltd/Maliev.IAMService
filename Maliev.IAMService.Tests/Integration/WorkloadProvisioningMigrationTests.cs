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
    private const string PreLegacyServiceCleanupMigration = "20260715231400_HardenWorkloadPrincipalProvisioning";

    [Fact]
    public async Task LegacyServiceCleanup_RemovesPlatformOwnerBindingsFromNonHumanPrincipals()
    {
        var schema = CreateSchemaName();
        await CreateSchemaAsync(schema);
        try
        {
            await using var context = CreateContext(schema);
            var migrator = context.GetService<IMigrator>();
            await migrator.MigrateAsync(PreLegacyServiceCleanupMigration);

            var humanId = Guid.NewGuid();
            var legacyServiceId = Guid.NewGuid();
            var workloadId = Guid.NewGuid();
            var now = DateTime.UtcNow;
            await context.Database.ExecuteSqlInterpolatedAsync(
                $"""
                 INSERT INTO roles
                     (role_id, service_name, role_name, description, is_custom, created_by, created_at, updated_at)
                 VALUES
                     ('roles.platform.owner', 'platform', 'Platform Owner', 'Full administrative access', FALSE, NULL, {now}, {now})
                 """);
            await context.Database.ExecuteSqlInterpolatedAsync(
                $"""
                 INSERT INTO principals
                     (principal_id, principal_type, email, display_name, is_active, created_at, updated_at, workload_id)
                 VALUES
                     ({humanId}, 'user', 'owner@maliev.com', 'Human owner', TRUE, {now}, {now}, NULL),
                     ({legacyServiceId}, 'system', 'system:service:pricing@serviceaccount.maliev.local', 'Legacy service', TRUE, {now}, {now}, NULL),
                     ({workloadId}, 'service_account', 'pricing-service@workload.maliev.local', 'Managed workload', TRUE, {now}, {now}, 'pricing-service')
                 """);
            await context.Database.ExecuteSqlInterpolatedAsync(
                $"""
                 INSERT INTO principal_role_bindings
                     (binding_id, principal_id, role_id, resource_path, granted_by, granted_at, expires_at)
                 VALUES
                     ({Guid.NewGuid()}, {humanId}, 'roles.platform.owner', '*', {humanId}, {now}, NULL),
                     ({Guid.NewGuid()}, {legacyServiceId}, 'roles.platform.owner', '*', {humanId}, {now}, NULL),
                     ({Guid.NewGuid()}, {workloadId}, 'roles.platform.owner', '*', {humanId}, {now}, NULL)
                 """);

            await migrator.MigrateAsync();

            var remaining = await context.Database
                .SqlQuery<Guid>($"SELECT principal_id AS \"Value\" FROM principal_role_bindings WHERE role_id = 'roles.platform.owner' ORDER BY principal_id")
                .ToListAsync();
            Assert.Contains(humanId, remaining);
            Assert.DoesNotContain(workloadId, remaining);
            Assert.DoesNotContain(legacyServiceId, remaining);

            var serviceGrant = await Assert.ThrowsAsync<PostgresException>(() =>
                context.Database.ExecuteSqlInterpolatedAsync(
                    $"""
                     INSERT INTO principal_role_bindings
                         (binding_id, principal_id, role_id, resource_path, granted_by, granted_at, expires_at)
                     VALUES
                         ({Guid.NewGuid()}, {workloadId}, 'roles.platform.owner', '*', {humanId}, {now}, NULL)
                     """));
            Assert.Equal(PostgresErrorCodes.CheckViolation, serviceGrant.SqlState);

            var humanTypeChange = await Assert.ThrowsAsync<PostgresException>(() =>
                context.Database.ExecuteSqlInterpolatedAsync(
                    $"UPDATE principals SET principal_type = 'service_account' WHERE principal_id = {humanId}"));
            Assert.Equal(PostgresErrorCodes.CheckViolation, humanTypeChange.SqlState);

            var rollbackFailure = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                migrator.MigrateAsync(PreLegacyServiceCleanupMigration));
            var rollback = Assert.IsType<PostgresException>(rollbackFailure.InnerException);
            Assert.Equal(PostgresErrorCodes.ObjectNotInPrerequisiteState, rollback.SqlState);
            Assert.Contains("cannot roll back", rollback.MessageText, StringComparison.Ordinal);
        }
        finally
        {
            await DropSchemaAsync(schema);
        }
    }

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
