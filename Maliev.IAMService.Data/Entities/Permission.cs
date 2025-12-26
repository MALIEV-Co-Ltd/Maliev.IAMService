using System.ComponentModel.DataAnnotations;

namespace Maliev.IAMService.Data.Entities;

public class Permission
{
    [Key]
    [MaxLength(255)]
    public string PermissionId { get; set; } = null!; // e.g., "invoice.invoices.create"

    [Required]
    [MaxLength(100)]
    public string ServiceName { get; set; } = null!;

    [Required]
    [MaxLength(100)]
    public string ResourceType { get; set; } = null!;

    [Required]
    [MaxLength(100)]
    public string Action { get; set; } = null!;

    public string? Description { get; set; }

    public DateTime RegisteredAt { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}
