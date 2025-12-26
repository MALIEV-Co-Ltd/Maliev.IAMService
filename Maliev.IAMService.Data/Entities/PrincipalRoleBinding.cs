using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Maliev.IAMService.Data.Entities;

public class PrincipalRoleBinding
{
    [Key]
    public Guid BindingId { get; set; }

    [Required]
    public Guid PrincipalId { get; set; }

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
    [Required]
    public Guid GrantedBy { get; set; }

    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;

    public DateTime? ExpiresAt { get; set; }

    // Navigation properties
    [ForeignKey(nameof(PrincipalId))]
    public virtual Principal Principal { get; set; } = null!;

    [ForeignKey(nameof(RoleId))]
    public virtual Role Role { get; set; } = null!;
}
