using System.ComponentModel.DataAnnotations;
using System.Net;

namespace Maliev.IAMService.Data.Entities;

public class IAMAuditLog
{
    [Key]
    public Guid LogId { get; set; }

    [Required]
    [MaxLength(50)]
    public string Action { get; set; } = null!; // GRANT_ROLE, REVOKE_ROLE, etc.

    public Guid? PrincipalId { get; set; }

    [MaxLength(255)]
    public string? RoleId { get; set; }

    [MaxLength(255)]
    public string? PermissionId { get; set; }

    [Required]
    public Guid PerformedBy { get; set; }

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public IPAddress? IpAddress { get; set; }

    public string? UserAgent { get; set; }

    public string? Details { get; set; } // JSON object
}
