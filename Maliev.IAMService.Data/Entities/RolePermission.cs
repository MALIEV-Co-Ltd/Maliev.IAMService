using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Maliev.IAMService.Data.Entities;

/// <summary>
/// Represents a permission assigned to a role.
/// </summary>
public class RolePermission
{
    /// <summary>
    /// Gets or sets the unique identifier of the role.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string RoleId { get; set; } = null!;

    /// <summary>
    /// Gets or sets the unique identifier of the permission.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string PermissionId { get; set; } = null!;

    /// <summary>
    /// Gets or sets the date and time when the permission was added to the role.
    /// </summary>
    public DateTime AddedAt { get; set; } = DateTime.UtcNow;

    // Navigation properties
    /// <summary>
    /// Gets or sets the associated role.
    /// </summary>
    [ForeignKey(nameof(RoleId))]
    public virtual Role Role { get; set; } = null!;

    /// <summary>
    /// Gets or sets the associated permission.
    /// </summary>
    [ForeignKey(nameof(PermissionId))]
    public virtual Permission Permission { get; set; } = null!;
}
