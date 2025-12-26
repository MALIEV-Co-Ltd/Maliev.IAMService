using System.Text.RegularExpressions;

namespace Maliev.IAMService.Api.Validators;

public static partial class PermissionFormatValidator
{
    private static readonly Regex PermissionFormatRegex = PermissionPattern();

    [GeneratedRegex(@"^[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+$", RegexOptions.Compiled)]
    private static partial Regex PermissionPattern();

    public static bool IsValid(string permissionId)
    {
        if (string.IsNullOrWhiteSpace(permissionId))
            return false;

        if (!PermissionFormatRegex.IsMatch(permissionId))
            return false;

        var parts = permissionId.Split('.');
        if (parts.Length != 3)
            return false;

        // Each part must be non-empty and lowercase with hyphens only
        return parts.All(p => !string.IsNullOrWhiteSpace(p) && p.All(c => char.IsLower(c) || char.IsDigit(c) || c == '-'));
    }

    public static (string Service, string Resource, string Action) Parse(string permissionId)
    {
        if (!IsValid(permissionId))
            throw new ArgumentException($"Invalid permission format: {permissionId}. Expected format: {{service}}.{{resource}}.{{action}}");

        var parts = permissionId.Split('.');
        return (parts[0], parts[1], parts[2]);
    }
}
