using System.Security.Cryptography;
using System.Text;

namespace Maliev.IAMService.Application.Services;

/// <summary>
/// Defines the versioned Redis namespace for effective IAM permission state.
/// </summary>
public static class IamPermissionCacheKeys
{
    /// <summary>
    /// Current permission-cache namespace. Incrementing this value invalidates all prior authority snapshots.
    /// </summary>
    public const string PrincipalPrefix = "iam:v2:principal:";

    /// <summary>Returns the prefix for all cached permission state belonging to a principal.</summary>
    public static string ForPrincipal(Guid principalId) => $"{PrincipalPrefix}{principalId}:";

    /// <summary>Returns the permission cache key for a principal and optional resource path.</summary>
    public static string ForPermissions(Guid principalId, string? resourcePath = null)
    {
        var key = $"{ForPrincipal(principalId)}permissions";
        if (string.IsNullOrEmpty(resourcePath))
        {
            return key;
        }

        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(resourcePath.ToLowerInvariant()));
        return $"{key}:path:{Convert.ToHexString(hashBytes).ToLowerInvariant()}";
    }
}
