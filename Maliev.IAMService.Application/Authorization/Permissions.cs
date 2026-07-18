namespace Maliev.IAMService.Application.Authorization;

/// <summary>
/// Defines the permissions for the IAM Service.
/// </summary>
public static class IAMPermissions
{
    public const string PrincipalCreate = "iam.principals.create";
    public const string PrincipalRead = "iam.principals.read";
    public const string PrincipalUpdate = "iam.principals.update";
    public const string PrincipalDelete = "iam.principals.delete";
    public const string PrincipalList = "iam.principals.list";
    public const string WorkloadPrincipalProvision = "iam.workload-principals.provision";

    public const string RoleCreate = "iam.roles.create";
    public const string RoleRead = "iam.roles.read";
    public const string RoleUpdate = "iam.roles.update";
    public const string RoleDelete = "iam.roles.delete";
    public const string RoleList = "iam.roles.list";

    public const string PermissionCreate = "iam.permissions.create";
    public const string PermissionRead = "iam.permissions.read";
    public const string PermissionUpdate = "iam.permissions.update";
    public const string PermissionDelete = "iam.permissions.delete";
    public const string PermissionList = "iam.permissions.list";

    public const string BindingCreate = "iam.bindings.create";
    public const string BindingRead = "iam.bindings.read";
    public const string BindingDelete = "iam.bindings.delete";
    public const string BindingList = "iam.bindings.list";

    public const string AuthResolvePermissions = "iam.auth.resolve-permissions";
    public const string AuthCheckPermission = "iam.auth.check-permission";
    public const string AuthIssueToken = "iam.auth.issue-token";
    public const string AuthRefreshToken = "iam.auth.refresh-token";

    public const string AuditRead = "iam.audit.read";
    public const string AuditList = "iam.audit.list";

    public static readonly IReadOnlyDictionary<string, string> AllWithDescriptions = new Dictionary<string, string>
    {
        { PrincipalCreate, "Create IAM principals" },
        { PrincipalRead, "Read IAM principals" },
        { PrincipalUpdate, "Update IAM principals" },
        { PrincipalDelete, "Delete IAM principals" },
        { PrincipalList, "List IAM principals" },
        { WorkloadPrincipalProvision, "Provision server-owned workload principals" },
        { RoleCreate, "Create IAM roles" },
        { RoleRead, "Read IAM roles" },
        { RoleUpdate, "Update IAM roles" },
        { RoleDelete, "Delete IAM roles" },
        { RoleList, "List IAM roles" },
        { PermissionCreate, "Create permissions" },
        { PermissionRead, "Read permissions" },
        { PermissionUpdate, "Update permissions" },
        { PermissionDelete, "Delete permissions" },
        { PermissionList, "List permissions" },
        { BindingCreate, "Create IAM bindings" },
        { BindingRead, "Read IAM bindings" },
        { BindingDelete, "Delete IAM bindings" },
        { BindingList, "List IAM bindings" },
        { AuthResolvePermissions, "Resolve permissions for a principal" },
        { AuthCheckPermission, "Check if a principal has a permission" },
        { AuthIssueToken, "Issue authentication token" },
        { AuthRefreshToken, "Refresh authentication token" },
        { AuditRead, "Read audit logs" },
        { AuditList, "List audit logs" },
    };

    public static string[] All => AllWithDescriptions.Keys.ToArray();
}
