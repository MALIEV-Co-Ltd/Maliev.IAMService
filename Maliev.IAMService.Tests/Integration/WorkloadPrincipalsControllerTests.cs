using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Application.Workloads;
using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Tests.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Claims;

namespace Maliev.IAMService.Tests.Integration;

public sealed class WorkloadPrincipalsControllerTests(TestWebApplicationFactory factory) : BaseIntegrationTest(factory)
{
    private static readonly Guid ActorId = Guid.Parse("a0000000-0000-0000-0000-000000000001");
    private readonly HttpClient _employeeClient = factory.CreateEmployeeAdminClient(ActorId);

    [Fact]
    public async Task Put_EmployeeWithPermission_IdempotentlyCreatesCanonicalPrincipalAndExactBinding()
    {
        await PrepareAsync();
        var operationId = Guid.NewGuid();
        var request = new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId };

        var first = await _employeeClient.PutAsJsonAsync("/iam/v1/workload-principals/auth-service", request);
        var second = await _employeeClient.PutAsJsonAsync("/iam/v1/workload-principals/auth-service", request);

        Assert.True(first.StatusCode == HttpStatusCode.OK, await first.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var firstResult = await first.Content.ReadFromJsonAsync<WorkloadPrincipalResponse>();
        var secondResult = await second.Content.ReadFromJsonAsync<WorkloadPrincipalResponse>();
        Assert.NotNull(firstResult);
        Assert.NotNull(secondResult);
        Assert.Equal(firstResult.PrincipalId, secondResult.PrincipalId);

        await using var db = Factory.CreateDbContext();
        var principal = await db.Principals.SingleAsync(candidate => candidate.WorkloadId == "auth-service");
        Assert.Equal("service_account", principal.PrincipalType);
        Assert.True(principal.IsActive);
        var binding = await db.PrincipalRoleBindings.SingleAsync(candidate => candidate.PrincipalId == principal.PrincipalId);
        Assert.Equal("roles.workloads.auth-service.v1", binding.RoleId);
        Assert.Null(binding.ResourcePath);
        Assert.Empty(await db.ServiceAccountApiKeys.Where(candidate => candidate.PrincipalId == principal.PrincipalId).ToListAsync());
        Assert.Single(await db.WorkloadProvisioningOperations.Where(candidate => candidate.OperationId == operationId).ToListAsync());
        Assert.Contains(await db.IAMAuditLogs.ToListAsync(), candidate => candidate.Action == "PROVISION_WORKLOAD_PRINCIPAL");
    }

    [Fact]
    public async Task Put_ReusedOperationWithDifferentRequest_ReturnsConflict()
    {
        await PrepareAsync();
        var operationId = Guid.NewGuid();

        var first = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId });
        await using (var db = Factory.CreateDbContext())
        {
            var operation = await db.WorkloadProvisioningOperations.SingleAsync(candidate => candidate.OperationId == operationId);
            operation.RequestHash = new string('0', 64);
            await db.SaveChangesAsync();
        }

        var conflict = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId });

        Assert.True(first.StatusCode == HttpStatusCode.OK, await first.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
    }

    [Fact]
    public async Task Database_ProvisionedWorkloadId_IsImmutable()
    {
        await PrepareAsync();
        var response = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await using var db = Factory.CreateDbContext();
        var principal = await db.Principals.SingleAsync(candidate => candidate.WorkloadId == "auth-service");
        principal.WorkloadId = "renamed-service";

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task Put_MissingProfilePermission_RollsBackPrincipalOperationAndAudit()
    {
        await CleanDatabaseAsync();
        await SeedActorAsync(ActorId, "user", true);

        var response = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        await using var db = Factory.CreateDbContext();
        Assert.Empty(await db.Principals.Where(candidate => candidate.WorkloadId == "auth-service").ToListAsync());
        Assert.Empty(await db.WorkloadProvisioningOperations.ToListAsync());
        Assert.Empty(await db.IAMAuditLogs.Where(candidate => candidate.Action == "PROVISION_WORKLOAD_PRINCIPAL").ToListAsync());
    }

    [Fact]
    public async Task Put_ServiceCallerEvenWithPermission_ReturnsForbidden()
    {
        await CleanDatabaseAsync();
        var client = Factory.CreateLivePermissionCheckServiceClient();

        var response = await client.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Put_EmployeeClaimWithoutPrincipal_ReturnsForbidden()
    {
        await CleanDatabaseAsync();
        await SeedPermissionAsync("iam.auth.resolve-permissions");

        var response = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("user", false)]
    [InlineData("service_account", true)]
    public async Task Put_InactiveOrNonUserActor_ReturnsForbidden(string principalType, bool isActive)
    {
        await CleanDatabaseAsync();
        await SeedPermissionAsync("iam.auth.resolve-permissions");
        await SeedActorAsync(ActorId, principalType, isActive);

        var response = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Put_DuplicateSubjectClaims_ReturnsForbidden()
    {
        await PrepareAsync();
        var client = Factory.CreateEmployeeAdminClient(ActorId, new Claim("sub", ActorId.ToString("D")));

        var response = await client.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Put_DuplicateUserTypeClaims_ReturnsForbidden()
    {
        await PrepareAsync();
        var client = Factory.CreateEmployeeAdminClient(ActorId, new Claim("user_type", "employee"));

        var response = await client.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Put_ConflictingUserTypeClaims_ReturnsForbidden()
    {
        await PrepareAsync();
        var client = Factory.CreateEmployeeAdminClient(ActorId, new Claim("user_type", "service"));

        var response = await client.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Put_MissingUserTypeClaim_ReturnsForbidden()
    {
        await PrepareAsync();
        var token = Factory.CreateTestJwtToken(
            ActorId.ToString("D"),
            roles: ["employee"],
            permissions: ["iam.workload-principals.provision"]);
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var response = await client.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("a0000000-0000-0000-0000-000000000001")]
    [InlineData("{a0000000-0000-0000-0000-000000000001}")]
    public async Task Put_NonCanonicalSubject_ReturnsForbidden(string subject)
    {
        await PrepareAsync();
        var token = Factory.CreateTestJwtToken(
            subject.ToUpperInvariant(),
            roles: ["employee"],
            permissions: ["iam.workload-principals.provision"],
            additionalClaims: new Dictionary<string, string> { ["user_type"] = "employee" });
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var response = await client.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Put_Unauthenticated_ReturnsUnauthorized()
    {
        await CleanDatabaseAsync();
        var client = Factory.CreateClient();

        var response = await client.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("*", false)]
    [InlineData("projects/project-1", false)]
    [InlineData(null, true)]
    public async Task Put_ReplayAfterAnyDirectPermissionDrift_ReturnsConflict(string? resourcePath, bool expired)
    {
        await PrepareAsync();
        var operationId = Guid.NewGuid();
        var first = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId });
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        await using (var db = Factory.CreateDbContext())
        {
            var principalId = await db.Principals.Where(item => item.WorkloadId == "auth-service").Select(item => item.PrincipalId).SingleAsync();
            db.PrincipalPermissionBindings.Add(new PrincipalPermissionBinding
            {
                BindingId = Guid.NewGuid(),
                PrincipalId = principalId,
                PermissionId = "iam.auth.resolve-permissions",
                ResourcePath = resourcePath,
                GrantedAt = DateTime.UtcNow,
                ExpiresAt = expired ? DateTime.UtcNow.AddMinutes(-1) : null
            });
            await db.SaveChangesAsync();
        }

        var replay = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId });

        Assert.Equal(HttpStatusCode.Conflict, replay.StatusCode);
    }

    [Fact]
    public async Task Put_SameOperationByDifferentEmployee_ReturnsConflict()
    {
        await PrepareAsync();
        var otherActorId = Guid.Parse("b0000000-0000-0000-0000-000000000002");
        await SeedActorAsync(otherActorId, "user", true);
        var operationId = Guid.NewGuid();
        var first = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId });
        var otherClient = Factory.CreateEmployeeAdminClient(otherActorId);

        var replay = await otherClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId });

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, replay.StatusCode);
    }

    [Fact]
    public async Task Put_ConcurrentSameOperation_ReturnsSamePrincipal()
    {
        await PrepareAsync();
        var request = new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() };

        var responses = await Task.WhenAll(
            _employeeClient.PutAsJsonAsync("/iam/v1/workload-principals/auth-service", request),
            _employeeClient.PutAsJsonAsync("/iam/v1/workload-principals/auth-service", request));

        Assert.All(responses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
        var results = await Task.WhenAll(responses.Select(response => response.Content.ReadFromJsonAsync<WorkloadPrincipalResponse>()));
        Assert.All(results, Assert.NotNull);
        Assert.Equal(results[0]!.PrincipalId, results[1]!.PrincipalId);
    }

    [Fact]
    public async Task Put_ConcurrentDifferentOperations_ReconcilesOnePrincipalAndBinding()
    {
        await PrepareAsync();

        var responses = await Task.WhenAll(
            _employeeClient.PutAsJsonAsync("/iam/v1/workload-principals/auth-service", new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() }),
            _employeeClient.PutAsJsonAsync("/iam/v1/workload-principals/auth-service", new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() }));

        Assert.All(responses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
        await using var db = Factory.CreateDbContext();
        var principal = await db.Principals.SingleAsync(item => item.WorkloadId == "auth-service");
        Assert.Single(await db.PrincipalRoleBindings.Where(item => item.PrincipalId == principal.PrincipalId).ToListAsync());
        Assert.Equal(2, await db.WorkloadProvisioningOperations.CountAsync());
    }

    [Fact]
    public async Task GenericGrantRevokeDeleteAndRoleDelete_ManagedWorkload_ReturnConflict()
    {
        await PrepareAsync();
        var principalId = await ProvisionAsync();
        await using var db = Factory.CreateDbContext();
        var bindingId = await db.PrincipalRoleBindings
            .Where(item => item.PrincipalId == principalId)
            .Select(item => item.BindingId)
            .SingleAsync();

        var grant = await _employeeClient.PostAsJsonAsync(
            $"/iam/v1/principals/{principalId:D}/roles",
            new GrantRoleRequest { RoleId = "roles.workloads.auth-service.v1" });
        var revoke = await _employeeClient.DeleteAsync($"/iam/v1/principals/{principalId:D}/roles/{bindingId:D}");
        var deletePrincipal = await _employeeClient.DeleteAsync($"/iam/v1/principals/{principalId:D}");
        var deleteRole = await _employeeClient.DeleteAsync("/iam/v1/roles/roles.workloads.auth-service.v1");

        Assert.Equal(HttpStatusCode.Conflict, grant.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, revoke.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, deletePrincipal.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, deleteRole.StatusCode);
    }

    [Fact]
    public async Task GenericGrant_WorkloadRoleToOrdinaryPrincipal_ReturnsConflict()
    {
        await PrepareAsync();
        await ProvisionAsync();

        var response = await _employeeClient.PostAsJsonAsync(
            $"/iam/v1/principals/{ActorId:D}/roles",
            new GrantRoleRequest { RoleId = "roles.workloads.auth-service.v1" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        await using var db = Factory.CreateDbContext();
        Assert.False(await db.PrincipalRoleBindings.AnyAsync(item =>
            item.PrincipalId == ActorId && item.RoleId == "roles.workloads.auth-service.v1"));
    }

    [Fact]
    public async Task GenericRepository_WorkloadRoleToOrdinaryPrincipal_IsRejected()
    {
        await PrepareAsync();
        await ProvisionAsync();
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBindingRepository>();
        var binding = new PrincipalRoleBinding
        {
            BindingId = Guid.NewGuid(),
            PrincipalId = ActorId,
            RoleId = "roles.workloads.auth-service.v1",
            GrantedAt = DateTime.UtcNow,
            GrantedBy = ActorId
        };

        await Assert.ThrowsAsync<ManagedWorkloadMutationException>(() => repository.CreateAsync(binding));
    }

    [Fact]
    public async Task PrincipalRepository_ManagedWorkloadUpdate_IsRejected()
    {
        await PrepareAsync();
        var principalId = await ProvisionAsync();
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IPrincipalRepository>();
        var principal = await repository.GetByIdAsync(principalId);
        Assert.NotNull(principal);
        principal.DisplayName = "mutated";

        await Assert.ThrowsAsync<ManagedWorkloadMutationException>(() => repository.UpdateAsync(principal));
    }

    [Fact]
    public async Task RoleRepository_ManagedWorkloadMutations_AreRejected()
    {
        await PrepareAsync();
        await ProvisionAsync();
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IRoleRepository>();
        var existing = await repository.GetByIdAsync("roles.workloads.auth-service.v1");
        Assert.NotNull(existing);

        await Assert.ThrowsAsync<ManagedWorkloadMutationException>(() => repository.CreateAsync(new Role
        {
            RoleId = "roles.workloads.other-service.v1",
            RoleName = "Other workload",
            ServiceName = "workloads",
            IsCustom = false
        }));
        await Assert.ThrowsAsync<ManagedWorkloadMutationException>(() => repository.CreateManyAsync([new Role
        {
            RoleId = "roles.workloads.other-service.v1",
            RoleName = "Other workload",
            ServiceName = "workloads",
            IsCustom = false
        }]));
        await Assert.ThrowsAsync<ManagedWorkloadMutationException>(() => repository.UpdateAsync(existing));
        await Assert.ThrowsAsync<ManagedWorkloadMutationException>(() => repository.DeleteAsync(existing.RoleId));
    }

    [Fact]
    public async Task ApiKeyRepository_ManagedWorkloadCreateAndUpdate_AreRejected()
    {
        await PrepareAsync();
        var principalId = await ProvisionAsync();
        var keyId = Guid.NewGuid();
        var candidate = new ServiceAccountApiKey
        {
            KeyId = keyId,
            PrincipalId = principalId,
            KeyHash = "test-only-hash",
            KeyPrefix = "test-key",
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };
        using (var scope = Factory.Services.CreateScope())
        {
            var repository = scope.ServiceProvider.GetRequiredService<IServiceAccountApiKeyRepository>();
            await Assert.ThrowsAsync<ManagedWorkloadMutationException>(() => repository.CreateAsync(candidate));
        }

        await using (var db = Factory.CreateDbContext())
        {
            db.ServiceAccountApiKeys.Add(candidate);
            await db.SaveChangesAsync();
        }

        using var updateScope = Factory.Services.CreateScope();
        var updateRepository = updateScope.ServiceProvider.GetRequiredService<IServiceAccountApiKeyRepository>();
        var persisted = await updateRepository.GetByIdAsync(keyId);
        Assert.NotNull(persisted);
        persisted.KeyHash = "changed-test-only-hash";
        await Assert.ThrowsAsync<ManagedWorkloadMutationException>(() => updateRepository.UpdateAsync(persisted));
    }

    [Fact]
    public async Task DirectPermissionRepository_ManagedWorkload_RejectsEvenExpiredBinding()
    {
        await PrepareAsync();
        var principalId = await ProvisionAsync();
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBindingRepository>();
        var binding = new PrincipalPermissionBinding
        {
            BindingId = Guid.NewGuid(),
            PrincipalId = principalId,
            PermissionId = "iam.auth.resolve-permissions",
            ResourcePath = null,
            GrantedAt = DateTime.UtcNow.AddHours(-2),
            ExpiresAt = DateTime.UtcNow.AddHours(-1)
        };

        await Assert.ThrowsAsync<ManagedWorkloadMutationException>(
            () => repository.CreateDirectPermissionAsync(binding));
    }

    [Fact]
    public async Task Put_ReplayAfterRequiredBindingExpiryDrift_ReturnsConflict()
    {
        await PrepareAsync();
        var operationId = Guid.NewGuid();
        var principalId = await ProvisionAsync(operationId);
        await using (var db = Factory.CreateDbContext())
        {
            var binding = await db.PrincipalRoleBindings.SingleAsync(item => item.PrincipalId == principalId);
            binding.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
        }

        var replay = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId });

        Assert.Equal(HttpStatusCode.Conflict, replay.StatusCode);
    }

    [Fact]
    public async Task Database_DeleteManagedWorkloadPrincipal_IsRejectedAndAuditPreserved()
    {
        await PrepareAsync();
        var principalId = await ProvisionAsync();
        await using var db = Factory.CreateDbContext();
        var principal = await db.Principals.SingleAsync(item => item.PrincipalId == principalId);
        db.Principals.Remove(principal);

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        await using var verification = Factory.CreateDbContext();
        Assert.True(await verification.Principals.AnyAsync(item => item.PrincipalId == principalId));
        Assert.True(await verification.IAMAuditLogs.AnyAsync(item => item.PrincipalId == principalId));
    }

    [Fact]
    public async Task GenericApiKeyRotation_ManagedWorkload_ReturnsConflict()
    {
        await PrepareAsync();
        var principalId = await ProvisionAsync();

        var response = await _employeeClient.PostAsync(
            $"/iam/v1/service-accounts/{principalId:D}/rotate-key",
            null);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        await using var db = Factory.CreateDbContext();
        Assert.False(await db.ServiceAccountApiKeys.AnyAsync(item => item.PrincipalId == principalId));
    }

    [Fact]
    public async Task Put_ReplayAfterIamApiKeyDrift_ReturnsConflict()
    {
        await PrepareAsync();
        var operationId = Guid.NewGuid();
        var principalId = await ProvisionAsync(operationId);
        await using (var db = Factory.CreateDbContext())
        {
            db.ServiceAccountApiKeys.Add(new ServiceAccountApiKey
            {
                KeyId = Guid.NewGuid(),
                PrincipalId = principalId,
                KeyHash = "test-only-hash",
                KeyPrefix = "test-key",
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var replay = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId });

        Assert.Equal(HttpStatusCode.Conflict, replay.StatusCode);
    }

    [Fact]
    public async Task Database_DeleteOperationActor_IsRestricted()
    {
        await PrepareAsync();
        await ProvisionAsync();
        await using var db = Factory.CreateDbContext();
        var actor = await db.Principals.SingleAsync(item => item.PrincipalId == ActorId);
        db.Principals.Remove(actor);

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        await using var verification = Factory.CreateDbContext();
        Assert.True(await verification.Principals.AnyAsync(item => item.PrincipalId == ActorId));
        Assert.True(await verification.WorkloadProvisioningOperations.AnyAsync(item => item.PerformedBy == ActorId));
    }

    [Fact]
    public async Task Put_EmployeeWithoutProvisionPermission_ReturnsForbidden()
    {
        await CleanDatabaseAsync();
        var token = Factory.CreateTestJwtToken(
            Guid.NewGuid().ToString(),
            roles: ["employee"],
            permissions: ["iam.principals.read"],
            additionalClaims: new Dictionary<string, string> { ["user_type"] = "employee" });
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var response = await client.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private async Task SeedPermissionAsync(string permissionId)
    {
        await using var db = Factory.CreateDbContext();
        db.Permissions.Add(new Permission
        {
            PermissionId = permissionId,
            ServiceName = "iam",
            ResourceType = "auth",
            Action = "resolve-permissions"
        });
        await db.SaveChangesAsync();
    }

    private async Task PrepareAsync()
    {
        await CleanDatabaseAsync();
        await SeedPermissionAsync("iam.auth.resolve-permissions");
        await SeedActorAsync(ActorId, "user", true);
    }

    private async Task SeedActorAsync(Guid principalId, string principalType, bool isActive)
    {
        await using var db = Factory.CreateDbContext();
        db.Principals.Add(new Principal
        {
            PrincipalId = principalId,
            PrincipalType = principalType,
            Email = $"{principalId:D}@example.test",
            DisplayName = "Test employee",
            IsActive = isActive,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
    }

    private async Task<Guid> ProvisionAsync(Guid? operationId = null)
    {
        var response = await _employeeClient.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId ?? Guid.NewGuid() });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<WorkloadPrincipalResponse>();
        Assert.NotNull(result);
        return result.PrincipalId;
    }
}
