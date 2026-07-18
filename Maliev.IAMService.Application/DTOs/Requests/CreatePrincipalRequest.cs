namespace Maliev.IAMService.Application.DTOs.Requests;

/// <summary>Request model for creating a principal in IAM.</summary>
public record CreatePrincipalRequest
{
    /// <summary>Type of principal (e.g., "user", "service_account").</summary>
    public string PrincipalType { get; init; } = "user";
    /// <summary>Email address of the principal.</summary>
    public string? Email { get; init; }
    /// <summary>Display name for the principal.</summary>
    public string? DisplayName { get; init; }
    /// <summary>Service that owns this principal link.</summary>
    public string? LinkedService { get; init; }
    /// <summary>External entity ID for linked principals.</summary>
    public Guid? LinkedEntityId { get; init; }
}
