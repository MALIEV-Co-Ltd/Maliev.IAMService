using System.ComponentModel.DataAnnotations;

namespace Maliev.IAMService.Domain.Entities;

/// <summary>
/// Represents a role that can be assigned to a principal.
/// </summary>
public class Role
{
    /// <summary>
    /// Gets or sets the unique identifier for the role.
    /// </summary>
    [Key]
    [MaxLength(255)]
    public string RoleId { get; set; } = null!;

    /// <summary>
    /// Gets or sets the service name associated with the role. Null for custom roles.
    /// </summary>
    [MaxLength(100)]
    public string? ServiceName { get; set; }

    /// <summary>
    /// Gets or sets the name of the role.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string RoleName { get; set; } = null!;

    /// <summary>
    /// Gets or sets the description of the role.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the role is a custom role.
    /// </summary>
    public bool IsCustom { get; set; } = false;

    /// <summary>
    /// Gets or sets the unique identifier of the user who created the role.
    /// </summary>
    public Guid? CreatedBy { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the role was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the date and time when the role was last updated.
    /// </summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the collection of permissions associated with the role.
    /// </summary>
    public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();

    /// <summary>
    /// Gets or sets the collection of principal bindings associated with the role.
    /// </summary>
    public virtual ICollection<PrincipalRoleBinding> PrincipalBindings { get; set; } = new List<PrincipalRoleBinding>();
}
