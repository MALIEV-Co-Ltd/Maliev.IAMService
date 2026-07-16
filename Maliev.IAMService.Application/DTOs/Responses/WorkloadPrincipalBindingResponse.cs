namespace Maliev.IAMService.Application.DTOs.Responses;

/// <summary>Describes one exact role binding owned by a workload profile.</summary>
public sealed record WorkloadPrincipalBindingResponse
{
    /// <summary>Gets the server-owned role identifier.</summary>
    public required string RoleId { get; init; }

    /// <summary>Gets the resource root, or <see langword="null"/> for a global binding.</summary>
    public string? ResourcePath { get; init; }
}
