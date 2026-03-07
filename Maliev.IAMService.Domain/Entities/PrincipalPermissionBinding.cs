using System.ComponentModel.DataAnnotations;

namespace Maliev.IAMService.Domain.Entities;

/// <summary>
/// Represents a direct binding between a principal and a granular permission.
/// Used for "inline" permission assignments that bypass the standard Role-Based Access Control (RBAC).
/// </summary>
public class PrincipalPermissionBinding
{
    /// <summary>
    /// Gets or sets the unique identifier for this binding.
    /// </summary>
    [Key]
    public Guid BindingId { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the principal (user or service account).
    /// </summary>
    [Required]
    public Guid PrincipalId { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the permission (e.g., "customer.profile.read").
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string PermissionId { get; set; } = null!;

    /// <summary>
    /// Gets or sets the optional hierarchical path to which this permission applies.
    /// If null or "*", the permission applies globally across all resources.
    /// </summary>
    [MaxLength(512)]
    public string? ResourcePath { get; set; } = "*";

    /// <summary>
    /// Gets or sets the UTC timestamp when this binding was granted.
    /// </summary>
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the optional UTC timestamp when this binding expires.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// Gets or sets the principal associated with this binding.
    /// </summary>
    public virtual Principal Principal { get; set; } = null!;

    /// <summary>
    /// Gets or sets the permission associated with this binding.
    /// </summary>
    public virtual Permission Permission { get; set; } = null!;
}
