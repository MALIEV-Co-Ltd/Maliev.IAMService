namespace Maliev.IAMService.Application.DTOs.Responses;

/// <summary>
/// Response model for a principal (User or Service Account) in the IAM system.
/// </summary>
public class PrincipalResponse
{
    /// <summary>Gets or sets the unique identifier of the principal.</summary>
    public Guid PrincipalId { get; set; }

    /// <summary>Gets or sets the type of principal (user, service_account).</summary>
    public string PrincipalType { get; set; } = string.Empty;

    /// <summary>Gets or sets the email address.</summary>
    public string? Email { get; set; }

    /// <summary>Gets or sets the display name.</summary>
    public string? DisplayName { get; set; }

    /// <summary>Gets or sets the name of the linked service.</summary>
    public string? LinkedService { get; set; }

    /// <summary>Gets or sets the unique identifier in the linked service.</summary>
    public Guid? LinkedEntityId { get; set; }

    /// <summary>Gets or sets a value indicating whether the principal is active.</summary>
    public bool IsActive { get; set; }

    /// <summary>Gets or sets the date and time the principal was created.</summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>Gets or sets the date and time the principal was last updated.</summary>
    public DateTime UpdatedAt { get; set; }
}
