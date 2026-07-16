namespace Maliev.IAMService.Application.DTOs.Responses;

/// <summary>Describes a provisioned workload principal.</summary>
public sealed record WorkloadPrincipalResponse
{
    /// <summary>Gets the canonical workload identifier.</summary>
    public required string WorkloadId { get; init; }

    /// <summary>Gets the IAM principal identifier.</summary>
    public required Guid PrincipalId { get; init; }

    /// <summary>Gets the applied server-owned profile version.</summary>
    public required int ProfileVersion { get; init; }

    /// <summary>Gets the exact bound role identifier.</summary>
    public required string RoleId { get; init; }

    /// <summary>Gets all exact role bindings applied by the workload profile.</summary>
    public IReadOnlyList<WorkloadPrincipalBindingResponse> Bindings { get; init; } = [];
}
