using System.ComponentModel.DataAnnotations;

namespace Maliev.IAMService.Application.DTOs.Requests;

/// <summary>Requests idempotent provisioning of a server-owned workload profile.</summary>
public sealed record ProvisionWorkloadPrincipalRequest
{
    /// <summary>Gets the profile version.</summary>
    [Range(1, int.MaxValue)]
    public required int ProfileVersion { get; init; }

    /// <summary>Gets the caller-generated idempotency operation identifier.</summary>
    public required Guid OperationId { get; init; }
}
