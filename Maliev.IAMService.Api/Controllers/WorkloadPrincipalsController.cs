using Asp.Versioning;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.Workloads;
using Maliev.IAMService.Domain.Constants;
using Microsoft.AspNetCore.Mvc;

namespace Maliev.IAMService.Api.Controllers;

/// <summary>Employee administration endpoint for canonical workload principals.</summary>
[ApiController]
[ApiVersion("1")]
[Route("iam/v{version:apiVersion}/workload-principals")]
public sealed class WorkloadPrincipalsController(IWorkloadPrincipalProvisioner provisioner) : ControllerBase
{
    /// <summary>Creates or reconciles a workload principal from a server-owned access profile.</summary>
    /// <param name="workloadId">Canonical workload identifier.</param>
    /// <param name="request">Idempotent provisioning request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The provisioned principal.</returns>
    [HttpPut("{workloadId}")]
    [RequirePermission(IAMPermissions.WorkloadPrincipalsProvision)]
    public async Task<IActionResult> Put(
        string workloadId,
        [FromBody] ProvisionWorkloadPrincipalRequest request,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(User.FindFirst("user_type")?.Value, "employee", StringComparison.Ordinal))
        {
            return Forbid();
        }

        if (!Guid.TryParse(User.FindFirst("sub")?.Value, out var performedBy) || performedBy == Guid.Empty)
        {
            return Forbid();
        }

        try
        {
            return Ok(await provisioner.ProvisionAsync(workloadId, request, performedBy, cancellationToken));
        }
        catch (WorkloadProvisioningConflictException exception)
        {
            return Conflict(new { error = exception.Message });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { error = exception.Message });
        }
    }
}
