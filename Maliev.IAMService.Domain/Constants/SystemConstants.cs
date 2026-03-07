namespace Maliev.IAMService.Domain.Constants;

/// <summary>
/// System-level constants for the IAM domain.
/// </summary>
public static class SystemConstants
{
    /// <summary>
    /// Sentinel GUID used for system-level actions where no real principal is acting.
    /// </summary>
    public static readonly Guid SystemPrincipalId = new("00000000-0000-0000-0000-000000000001");
}
