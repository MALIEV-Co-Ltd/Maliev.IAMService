namespace Maliev.IAMService.Domain.Constants;

/// <summary>
/// IAM Service permission constants following GCP-style naming convention.
/// Format: {service}.{resource}.{action}
/// </summary>
public static class IAMPermissions
{
    // Principal Management
    /// <summary>Permission to create a new principal.</summary>
    public const string PrincipalsCreate = "iam.principals.create";
    /// <summary>Permission to read principal details.</summary>
    public const string PrincipalsRead = "iam.principals.read";
    /// <summary>Permission to update a principal.</summary>
    public const string PrincipalsUpdate = "iam.principals.update";
    /// <summary>Permission to delete a principal.</summary>
    public const string PrincipalsDelete = "iam.principals.delete";
    /// <summary>Permission to list principals.</summary>
    public const string PrincipalsList = "iam.principals.list";

    // Role Management
    /// <summary>Permission to create a new role.</summary>
    public const string RolesCreate = "iam.roles.create";
    /// <summary>Permission to read role details.</summary>
    public const string RolesRead = "iam.roles.read";
    /// <summary>Permission to update a role.</summary>
    public const string RolesUpdate = "iam.roles.update";
    /// <summary>Permission to delete a role.</summary>
    public const string RolesDelete = "iam.roles.delete";
    /// <summary>Permission to list roles.</summary>
    public const string RolesList = "iam.roles.list";

    // Permission Management
    /// <summary>Permission to create a new permission.</summary>
    public const string PermissionsCreate = "iam.permissions.create";
    /// <summary>Permission to read permission details.</summary>
    public const string PermissionsRead = "iam.permissions.read";
    /// <summary>Permission to update a permission.</summary>
    public const string PermissionsUpdate = "iam.permissions.update";
    /// <summary>Permission to delete a permission.</summary>
    public const string PermissionsDelete = "iam.permissions.delete";
    /// <summary>Permission to list permissions.</summary>
    public const string PermissionsList = "iam.permissions.list";

    // Binding Management (role assignments)
    /// <summary>Permission to create a new role binding.</summary>
    public const string BindingsCreate = "iam.bindings.create";
    /// <summary>Permission to read role binding details.</summary>
    public const string BindingsRead = "iam.bindings.read";
    /// <summary>Permission to delete a role binding.</summary>
    public const string BindingsDelete = "iam.bindings.delete";
    /// <summary>Permission to list role bindings.</summary>
    public const string BindingsList = "iam.bindings.list";

    // Authorization Operations (permission checks, token issuance)
    /// <summary>Permission to resolve effective permissions for a principal.</summary>
    public const string AuthResolvePermissions = "iam.auth.resolve-permissions";
    /// <summary>Permission to check a specific permission for a principal.</summary>
    public const string AuthCheckPermission = "iam.auth.check-permission";
    /// <summary>Permission to issue a token for a principal.</summary>
    public const string AuthIssueToken = "iam.auth.issue-token";
    /// <summary>Permission to refresh a token.</summary>
    public const string AuthRefreshToken = "iam.auth.refresh-token";

    // Audit Logs
    /// <summary>Permission to read audit logs.</summary>
    public const string AuditRead = "iam.audit.read";
    /// <summary>Permission to list audit logs.</summary>
    public const string AuditList = "iam.audit.list";

    /// <summary>
    /// All IAM permissions for convenience in role definitions.
    /// </summary>
    public static readonly string[] All =
    [
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
    ];

    /// <summary>
    /// Read-only permissions for auditing and viewing.
    /// </summary>
    public static readonly string[] ReadOnly =
    [
        PrincipalsRead, PrincipalsList,
        RolesRead, RolesList,
        PermissionsRead, PermissionsList,
        BindingsRead, BindingsList,
        AuthResolvePermissions, AuthCheckPermission,
        AuditRead, AuditList
    ];

    /// <summary>
    /// Administrative permissions requiring high security.
    /// </summary>
    public static readonly string[] Admin =
    [
        PrincipalsCreate, PrincipalsUpdate, PrincipalsDelete,
        RolesCreate, RolesUpdate, RolesDelete,
        PermissionsCreate, PermissionsUpdate, PermissionsDelete,
        BindingsCreate, BindingsDelete
    ];
}
