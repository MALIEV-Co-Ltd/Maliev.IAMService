namespace Maliev.IAMService.Api.Models.Requests;

public record RevokeRoleRequest
{
    public required Guid BindingId { get; init; }
}
