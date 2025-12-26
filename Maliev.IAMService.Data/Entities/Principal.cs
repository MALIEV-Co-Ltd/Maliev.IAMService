using System.ComponentModel.DataAnnotations;

namespace Maliev.IAMService.Data.Entities;

public class Principal
{
    [Key]
    public Guid PrincipalId { get; set; }

    [Required]
    [MaxLength(50)]
    public string PrincipalType { get; set; } = null!; // "user" or "service_account"

    [MaxLength(255)]
    public string? Email { get; set; }

    [MaxLength(255)]
    public string? DisplayName { get; set; }

    public bool IsActive { get; set; } = true;

    // Links to business profile services
    [MaxLength(100)]
    public string? LinkedService { get; set; } // 'CustomerService', 'EmployeeService', NULL

    public Guid? LinkedEntityId { get; set; } // FK to customer_id or employee_id

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public virtual ICollection<PrincipalRoleBinding> RoleBindings { get; set; } = new List<PrincipalRoleBinding>();
}
