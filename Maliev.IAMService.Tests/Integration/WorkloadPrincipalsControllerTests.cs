using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Tests.Testing;
using Microsoft.EntityFrameworkCore;

namespace Maliev.IAMService.Tests.Integration;

public sealed class WorkloadPrincipalsControllerTests(TestWebApplicationFactory factory) : BaseIntegrationTest(factory)
{
    [Fact]
    public async Task Put_EmployeeWithPermission_IdempotentlyCreatesCanonicalPrincipalAndExactBinding()
    {
        await CleanDatabaseAsync();
        await SeedPermissionAsync("iam.auth.resolve-permissions");
        var operationId = Guid.NewGuid();
        var request = new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId };

        var first = await Client.PutAsJsonAsync("/iam/v1/workload-principals/auth-service", request);
        var second = await Client.PutAsJsonAsync("/iam/v1/workload-principals/auth-service", request);

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
        await CleanDatabaseAsync();
        await SeedPermissionAsync("iam.auth.resolve-permissions");
        var operationId = Guid.NewGuid();

        var first = await Client.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId });
        await using (var db = Factory.CreateDbContext())
        {
            var operation = await db.WorkloadProvisioningOperations.SingleAsync(candidate => candidate.OperationId == operationId);
            operation.RequestHash = new string('0', 64);
            await db.SaveChangesAsync();
        }

        var conflict = await Client.PutAsJsonAsync(
            "/iam/v1/workload-principals/auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId });

        Assert.True(first.StatusCode == HttpStatusCode.OK, await first.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
    }

    [Fact]
    public async Task Database_ProvisionedWorkloadId_IsImmutable()
    {
        await CleanDatabaseAsync();
        await SeedPermissionAsync("iam.auth.resolve-permissions");
        var response = await Client.PutAsJsonAsync(
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

        var response = await Client.PutAsJsonAsync(
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
}
