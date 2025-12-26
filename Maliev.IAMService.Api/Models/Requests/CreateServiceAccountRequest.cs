namespace Maliev.IAMService.Api.Models.Requests;

public record CreateServiceAccountRequest
{
    public required string Name { get; init; }
    public string? Description { get; init; }
}
