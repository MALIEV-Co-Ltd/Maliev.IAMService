namespace Maliev.IAMService.Api.Models.Requests;

public record CreateUserPrincipalRequest
{
    public string? Email { get; init; }
    public string? LinkedService { get; init; }
    public Guid? LinkedEntityId { get; init; }
}
