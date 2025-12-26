using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Maliev.IAMService.Data.Entities;

public class RolePermission
{
    [Required]
    [MaxLength(255)]
    public string RoleId { get; set; } = null!;

    [Required]
    [MaxLength(255)]
    public string PermissionId { get; set; } = null!;

    public DateTime AddedAt { get; set; } = DateTime.UtcNow;

    // Navigation properties
    [ForeignKey(nameof(RoleId))]
    public virtual Role Role { get; set; } = null!;

    [ForeignKey(nameof(PermissionId))]
    public virtual Permission Permission { get; set; } = null!;
}
