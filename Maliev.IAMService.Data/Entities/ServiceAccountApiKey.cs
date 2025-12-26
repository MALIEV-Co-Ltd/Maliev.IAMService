using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Maliev.IAMService.Data.Entities;

public class ServiceAccountApiKey
{
    [Key]
    public Guid KeyId { get; set; }

    [Required]
    public Guid PrincipalId { get; set; }

    [Required]
    [MaxLength(255)]
    public string KeyHash { get; set; } = null!; // PBKDF2 hash

    [Required]
    [MaxLength(20)]
    public string KeyPrefix { get; set; } = null!; // First 8 chars for identification

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? LastUsedAt { get; set; }

    public DateTime? ExpiresAt { get; set; }

    public bool IsActive { get; set; } = true;

    // Navigation properties
    [ForeignKey(nameof(PrincipalId))]
    public virtual Principal Principal { get; set; } = null!;
}
