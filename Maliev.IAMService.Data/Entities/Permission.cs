using System.ComponentModel.DataAnnotations;

namespace Maliev.IAMService.Data.Entities;

/// <summary>
/// Represents a permission in the GCP-style format: {service}.{resource}.{action}.
/// </summary>
public class Permission
{
    /// <summary>
    /// Gets or sets the unique permission identifier in the format {service}.{resource}.{action} (e.g., "invoice.invoices.create").
    /// </summary>
    [Key]
    [MaxLength(255)]
    public string PermissionId { get; set; } = null!; // e.g., "invoice.invoices.create"

    /// <summary>
    /// Gets or sets the name of the service this permission belongs to (e.g., "invoice", "employee").
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string ServiceName { get; set; } = null!;

    /// <summary>
    /// Gets or sets the type of resource this permission controls access to (e.g., "invoices", "employees").
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string ResourceType { get; set; } = null!;

    /// <summary>
    /// Gets or sets the action that can be performed on the resource (e.g., "create", "read", "update", "delete").
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string Action { get; set; } = null!;

    /// <summary>
    /// Gets or sets a human-readable description of what this permission allows.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Gets or sets the UTC timestamp when this permission was registered with the IAM service.
    /// </summary>
    public DateTime RegisteredAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the collection of role-permission assignments that include this permission.
    /// </summary>
    public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();

    /// <summary>
    /// Gets or sets the collection of direct principal bindings assigned to this permission.
    /// </summary>
    public virtual ICollection<PrincipalPermissionBinding> PrincipalBindings { get; set; } = new List<PrincipalPermissionBinding>();
}
