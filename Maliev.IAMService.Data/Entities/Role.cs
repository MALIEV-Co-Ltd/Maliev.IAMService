using System.ComponentModel.DataAnnotations;

namespace Maliev.IAMService.Data.Entities;

public class Role
{
    [Key]
    [MaxLength(255)]
    public string RoleId { get; set; } = null!;

    [MaxLength(100)]
    public string? ServiceName { get; set; } // NULL for custom roles

    [Required]
    [MaxLength(255)]
    public string RoleName { get; set; } = null!;

    public string? Description { get; set; }

    public bool IsCustom { get; set; } = false;

    public Guid? CreatedBy { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
    public virtual ICollection<PrincipalRoleBinding> PrincipalBindings { get; set; } = new List<PrincipalRoleBinding>();
}
