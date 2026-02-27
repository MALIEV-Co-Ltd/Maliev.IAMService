using System.ComponentModel.DataAnnotations;
using System.Net;

namespace Maliev.IAMService.Domain.Entities;

/// <summary>
/// Represents an audit log entry for IAM operations such as role grants, revocations, and permission changes.
/// </summary>
public class IAMAuditLog
{
    /// <summary>
    /// Gets or sets the unique identifier for this audit log entry.
    /// </summary>
    [Key]
    public Guid LogId { get; set; }

    /// <summary>
    /// Gets or sets the action performed (e.g., GRANT_ROLE, REVOKE_ROLE, CREATE_PERMISSION).
    /// </summary>
    [Required]
    [MaxLength(50)]
    public string Action { get; set; } = null!;

    /// <summary>
    /// Gets or sets the ID of the principal affected by this action, if applicable.
    /// </summary>
    public Guid? PrincipalId { get; set; }

    /// <summary>
    /// Gets or sets the ID of the role involved in this action, if applicable.
    /// </summary>
    [MaxLength(255)]
    public string? RoleId { get; set; }

    /// <summary>
    /// Gets or sets the ID of the permission involved in this action, if applicable.
    /// </summary>
    [MaxLength(255)]
    public string? PermissionId { get; set; }

    /// <summary>
    /// Gets or sets the principal ID of the user or service account who performed this action.
    /// </summary>
    [Required]
    public Guid PerformedBy { get; set; }

    /// <summary>
    /// Gets or sets the UTC timestamp when this action was performed.
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the IP address from which the action was performed, if available.
    /// </summary>
    public IPAddress? IpAddress { get; set; }

    /// <summary>
    /// Gets or sets the user agent string of the client that performed the action, if available.
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Gets or sets additional details about the action in JSON format.
    /// </summary>
    public string? Details { get; set; }
}
