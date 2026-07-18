namespace Maliev.IAMService.Application.Authorization;

/// <summary>
/// Provides access to predefined roles for the IAM Service.
/// </summary>
public static class IAMPredefinedRoles
{
    public const string Admin = "roles.iam.admin";
    public const string Operator = "roles.iam.operator";
    public const string Viewer = "roles.iam.viewer";

    public static readonly IReadOnlyList<(string RoleId, string Description, string[] Permissions)> All = new List<(string, string, string[])>
    {
        (
            Admin,
            "IAM Administrator with full access",
            new[]
            {
                IAMPermissions.PrincipalCreate,
                IAMPermissions.PrincipalRead,
                IAMPermissions.PrincipalUpdate,
                IAMPermissions.PrincipalDelete,
                IAMPermissions.PrincipalList,
                IAMPermissions.WorkloadPrincipalProvision,
                IAMPermissions.RoleCreate,
                IAMPermissions.RoleRead,
                IAMPermissions.RoleUpdate,
                IAMPermissions.RoleDelete,
                IAMPermissions.RoleList,
                IAMPermissions.PermissionCreate,
                IAMPermissions.PermissionRead,
                IAMPermissions.PermissionUpdate,
                IAMPermissions.PermissionDelete,
                IAMPermissions.PermissionList,
                IAMPermissions.BindingCreate,
                IAMPermissions.BindingRead,
                IAMPermissions.BindingDelete,
                IAMPermissions.BindingList,
                IAMPermissions.AuthResolvePermissions,
                IAMPermissions.AuthCheckPermission,
                IAMPermissions.AuthIssueToken,
                IAMPermissions.AuthRefreshToken,
                IAMPermissions.AuditRead,
                IAMPermissions.AuditList,
            }
        ),
        (
            Operator,
            "IAM Operator with read-only access to principals and roles",
            new[]
            {
                IAMPermissions.PrincipalRead,
                IAMPermissions.PrincipalList,
                IAMPermissions.RoleRead,
                IAMPermissions.RoleList,
                IAMPermissions.PermissionRead,
                IAMPermissions.PermissionList,
                IAMPermissions.BindingRead,
                IAMPermissions.BindingList,
            }
        ),
        (
            Viewer,
            "IAM Viewer with audit read-only access",
            new[]
            {
                IAMPermissions.AuditRead,
                IAMPermissions.AuditList,
            }
        ),
    };
}
