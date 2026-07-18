using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;

namespace Maliev.IAMService.Application.Workloads;

/// <summary>Provisions canonical workload principals from server-owned profiles.</summary>
public interface IWorkloadPrincipalProvisioner
{
    /// <summary>Creates or reconciles a workload principal idempotently.</summary>
    /// <param name="workloadId">Canonical workload ID.</param>
    /// <param name="request">Provisioning request.</param>
    /// <param name="performedBy">Authenticated employee principal.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The provisioned principal.</returns>
    Task<WorkloadPrincipalResponse> ProvisionAsync(
        string workloadId,
        ProvisionWorkloadPrincipalRequest request,
        Guid performedBy,
        CancellationToken cancellationToken = default);
}

/// <summary>Signals an immutable or idempotency conflict during provisioning.</summary>
public sealed class WorkloadProvisioningConflictException : Exception
{
    /// <summary>Initializes a conflict exception.</summary>
    /// <param name="message">Safe conflict detail.</param>
    public WorkloadProvisioningConflictException(string message) : base(message)
    {
    }
}

/// <summary>Signals that the authenticated employee lacks current persisted provisioning authority.</summary>
public sealed class WorkloadProvisioningAuthorizationException : Exception
{
    /// <summary>Initializes an authorization exception.</summary>
    /// <param name="message">Safe authorization detail.</param>
    public WorkloadProvisioningAuthorizationException(string message) : base(message)
    {
    }
}

/// <summary>Signals an attempt to mutate a server-managed workload identity through a generic path.</summary>
public sealed class ManagedWorkloadMutationException : InvalidOperationException
{
    /// <summary>Initializes a managed-workload mutation exception.</summary>
    /// <param name="message">Safe conflict detail.</param>
    public ManagedWorkloadMutationException(string message) : base(message)
    {
    }
}
