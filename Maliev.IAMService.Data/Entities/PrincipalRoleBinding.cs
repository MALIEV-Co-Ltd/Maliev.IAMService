using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Maliev.IAMService.Data.Entities;

/// <summary>
/// Represents a binding between a principal (user or service account) and a role.
/// </summary>
public class PrincipalRoleBinding
{
    /// <summary>
    /// Gets or sets the unique identifier for the binding.
    /// </summary>
    [Key]
    public Guid BindingId { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the principal.
    /// </summary>
    [Required]
    public Guid PrincipalId { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the role.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string RoleId { get; set; } = null!;

    /// <summary>
    /// Hierarchical resource path for resource-scoped role bindings (e.g., "projects/123/datasets/456").
    /// Supports wildcards: /* (single-level) and /** (multi-level).
    /// NULL for global role bindings.
    /// </summary>
    [MaxLength(500)]
    public string? ResourcePath { get; set; }

    // Metadata
    /// <summary>
    /// Gets or sets the unique identifier of the user who granted the role.
    /// </summary>
    [Required]
    public Guid GrantedBy { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the role was granted.
    /// </summary>
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the date and time when the role binding expires.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    // Navigation properties
    /// <summary>
    /// Gets or sets the associated principal.
    /// </summary>
    [ForeignKey(nameof(PrincipalId))]
    public virtual Principal Principal { get; set; } = null!;

    /// <summary>
    /// Gets or sets the associated role.
    /// </summary>
    [ForeignKey(nameof(RoleId))]
    public virtual Role Role { get; set; } = null!;
}
