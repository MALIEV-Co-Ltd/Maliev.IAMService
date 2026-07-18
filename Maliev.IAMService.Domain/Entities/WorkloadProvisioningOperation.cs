using System.ComponentModel.DataAnnotations;

namespace Maliev.IAMService.Domain.Entities;

/// <summary>
/// Records an idempotent workload-principal provisioning operation.
/// </summary>
public sealed class WorkloadProvisioningOperation
{
    /// <summary>Gets or sets the caller-supplied idempotency operation identifier.</summary>
    [Key]
    public Guid OperationId { get; set; }

    /// <summary>Gets or sets the canonical workload identifier.</summary>
    [Required]
    [MaxLength(100)]
    public string WorkloadId { get; set; } = null!;

    /// <summary>Gets or sets the server-owned access profile version.</summary>
    public int ProfileVersion { get; set; }

    /// <summary>Gets or sets the SHA-256 hash of the canonical request.</summary>
    [Required]
    [MaxLength(64)]
    public string RequestHash { get; set; } = null!;

    /// <summary>Gets or sets the provisioned principal identifier.</summary>
    public Guid PrincipalId { get; set; }

    /// <summary>Gets or sets the employee principal that initiated the operation.</summary>
    public Guid PerformedBy { get; set; }

    /// <summary>Gets or sets the UTC completion time.</summary>
    public DateTime CompletedAt { get; set; }
}
