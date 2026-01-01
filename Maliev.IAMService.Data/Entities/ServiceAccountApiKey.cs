using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Maliev.IAMService.Data.Entities;

/// <summary>
/// Represents an API key for a service account.
/// </summary>
public class ServiceAccountApiKey
{
    /// <summary>
    /// Gets or sets the unique identifier for the API key.
    /// </summary>
    [Key]
    public Guid KeyId { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the principal (service account).
    /// </summary>
    [Required]
    public Guid PrincipalId { get; set; }

    /// <summary>
    /// Gets or sets the PBKDF2 hash of the API key.
    /// </summary>
    [Required]
    [MaxLength(255)]
    public string KeyHash { get; set; } = null!; // PBKDF2 hash

    /// <summary>
    /// Gets or sets the first 8 characters of the API key for identification.
    /// </summary>
    [Required]
    [MaxLength(20)]
    public string KeyPrefix { get; set; } = null!; // First 8 chars for identification

    /// <summary>
    /// Gets or sets the date and time when the API key was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the date and time when the API key was last used.
    /// </summary>
    public DateTime? LastUsedAt { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the API key expires.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the API key is active.
    /// </summary>
    public bool IsActive { get; set; } = true;

    // Navigation properties
    /// <summary>
    /// Gets or sets the associated principal.
    /// </summary>
    [ForeignKey(nameof(PrincipalId))]
    public virtual Principal Principal { get; set; } = null!;
}
