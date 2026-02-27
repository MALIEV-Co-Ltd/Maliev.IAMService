using System.Text.RegularExpressions;

namespace Maliev.IAMService.Application.Validators;

/// <summary>
/// Validator for permission ID formats.
/// Enforces {service}.{resource}.{action} format (e.g., "user-service.profile.update").
/// </summary>
public static partial class PermissionFormatValidator
{
    private static readonly Regex PermissionFormatRegex = PermissionPattern();

    [GeneratedRegex(@"^[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+$", RegexOptions.Compiled)]
    private static partial Regex PermissionPattern();

    /// <summary>
    /// Checks if a permission ID is valid.
    /// </summary>
    /// <param name="permissionId">The permission ID to validate.</param>
    /// <returns>True if the permission ID is valid; otherwise, false.</returns>
    public static bool IsValid(string permissionId)
    {
        if (string.IsNullOrWhiteSpace(permissionId))
            return false;

        if (!PermissionFormatRegex.IsMatch(permissionId))
            return false;

        var parts = permissionId.Split('.');
        if (parts.Length != 3)
            return false;

        return parts.All(p => !string.IsNullOrWhiteSpace(p) && p.All(c => char.IsLower(c) || char.IsDigit(c) || c == '-'));
    }

    /// <summary>
    /// Parses a permission ID into its component parts.
    /// </summary>
    /// <param name="permissionId">The permission ID to parse.</param>
    /// <returns>A tuple containing the service, resource, and action parts.</returns>
    /// <exception cref="ArgumentException">Thrown if the permission ID is invalid.</exception>
    public static (string Service, string Resource, string Action) Parse(string permissionId)
    {
        if (!IsValid(permissionId))
            throw new ArgumentException($"Invalid permission format: {permissionId}. Expected format: {{service}}.{{resource}}.{{action}}");

        var parts = permissionId.Split('.');
        return (parts[0], parts[1], parts[2]);
    }
}
