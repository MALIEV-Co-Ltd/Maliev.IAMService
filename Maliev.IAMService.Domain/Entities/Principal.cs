using System.ComponentModel.DataAnnotations;

namespace Maliev.IAMService.Domain.Entities;

/// <summary>
/// Represents an identity principal (user or service account) in the IAM system.
/// </summary>
public class Principal
{
    /// <summary>
    /// Gets or sets the unique identifier for this principal.
    /// </summary>
    [Key]
    public Guid PrincipalId { get; set; }

    /// <summary>
    /// Gets or sets the type of principal: "user" or "service_account".
    /// </summary>
    [Required]
    [MaxLength(50)]
    public string PrincipalType { get; set; } = null!;

    /// <summary>
    /// Gets or sets the email address associated with this principal, if applicable.
    /// </summary>
    [MaxLength(255)]
    public string? Email { get; set; }

    /// <summary>
    /// Gets or sets the display name for this principal.
    /// </summary>
    [MaxLength(255)]
    public string? DisplayName { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this principal is currently active.
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Gets the immutable canonical workload identifier for a provisioned workload principal.
    /// Null for human and legacy principals.
    /// </summary>
    [MaxLength(100)]
    public string? WorkloadId { get; set; }

    /// <summary>
    /// Gets or sets the name of the service this principal is linked to.
    /// </summary>
    [MaxLength(100)]
    public string? LinkedService { get; set; }

    /// <summary>
    /// Gets or sets the ID of the entity in the linked service.
    /// </summary>
    public Guid? LinkedEntityId { get; set; }

    /// <summary>
    /// Gets or sets the UTC timestamp when this principal was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the UTC timestamp when this principal was last updated.
    /// </summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the collection of role bindings assigned to this principal.
    /// </summary>
    public virtual ICollection<PrincipalRoleBinding> RoleBindings { get; set; } = new List<PrincipalRoleBinding>();

    /// <summary>
    /// Gets or sets the collection of direct permission bindings assigned to this principal.
    /// </summary>
    public virtual ICollection<PrincipalPermissionBinding> PermissionBindings { get; set; } = new List<PrincipalPermissionBinding>();
}
