namespace Maliev.IAMService.Api.Authorization;

/// <summary>
/// IAM Service permission constants following GCP-style naming convention.
/// Format: {service}.{resource}.{action}
/// </summary>
public static class IAMPermissions
{
    // Principal Management
    public const string PrincipalsCreate = "iam.principals.create";
    public const string PrincipalsRead = "iam.principals.read";
    public const string PrincipalsUpdate = "iam.principals.update";
    public const string PrincipalsDelete = "iam.principals.delete";
    public const string PrincipalsList = "iam.principals.list";

    // Role Management
    public const string RolesCreate = "iam.roles.create";
    public const string RolesRead = "iam.roles.read";
    public const string RolesUpdate = "iam.roles.update";
    public const string RolesDelete = "iam.roles.delete";
    public const string RolesList = "iam.roles.list";

    // Permission Management
    public const string PermissionsCreate = "iam.permissions.create";
    public const string PermissionsRead = "iam.permissions.read";
    public const string PermissionsUpdate = "iam.permissions.update";
    public const string PermissionsDelete = "iam.permissions.delete";
    public const string PermissionsList = "iam.permissions.list";

    // Binding Management (role assignments)
    public const string BindingsCreate = "iam.bindings.create";
    public const string BindingsRead = "iam.bindings.read";
    public const string BindingsDelete = "iam.bindings.delete";
    public const string BindingsList = "iam.bindings.list";

    // Authorization Operations (permission checks, token issuance)
    public const string AuthResolvePermissions = "iam.auth.resolve-permissions";
    public const string AuthCheckPermission = "iam.auth.check-permission";
    public const string AuthIssueToken = "iam.auth.issue-token";
    public const string AuthRefreshToken = "iam.auth.refresh-token";

    // Audit Logs
    public const string AuditRead = "iam.audit.read";
    public const string AuditList = "iam.audit.list";

    /// <summary>
    /// All IAM permissions for convenience in role definitions.
    /// </summary>
    public static readonly string[] All = new[]
    {
        // Principals
        PrincipalsCreate, PrincipalsRead, PrincipalsUpdate, PrincipalsDelete, PrincipalsList,
        // Roles
        RolesCreate, RolesRead, RolesUpdate, RolesDelete, RolesList,
        // Permissions
        PermissionsCreate, PermissionsRead, PermissionsUpdate, PermissionsDelete, PermissionsList,
        // Bindings
        BindingsCreate, BindingsRead, BindingsDelete, BindingsList,
        // Auth
        AuthResolvePermissions, AuthCheckPermission, AuthIssueToken, AuthRefreshToken,
        // Audit
        AuditRead, AuditList
    };

    /// <summary>
    /// Read-only permissions for auditing and viewing.
    /// </summary>
    public static readonly string[] ReadOnly = new[]
    {
        PrincipalsRead, PrincipalsList,
        RolesRead, RolesList,
        PermissionsRead, PermissionsList,
        BindingsRead, BindingsList,
        AuthResolvePermissions, AuthCheckPermission,
        AuditRead, AuditList
    };

    /// <summary>
    /// Administrative permissions requiring high security.
    /// </summary>
    public static readonly string[] Admin = new[]
    {
        PrincipalsCreate, PrincipalsUpdate, PrincipalsDelete,
        RolesCreate, RolesUpdate, RolesDelete,
        PermissionsCreate, PermissionsUpdate, PermissionsDelete,
        BindingsCreate, BindingsDelete
    };
}
