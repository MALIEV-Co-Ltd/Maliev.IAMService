namespace Maliev.IAMService.Api.Authorization;

/// <summary>
/// IAM Service permission constants for internal authorization
/// </summary>
public static class Permissions
{
    public const string ServiceName = "iam";

    // Permission management
    public const string RegisterPermissions = "iam.permissions.register";
    public const string ListPermissions = "iam.permissions.list";

    // Role management
    public const string RegisterRoles = "iam.roles.register";
    public const string ListRoles = "iam.roles.list";
    public const string CreateCustomRole = "iam.roles.create";
    public const string UpdateCustomRole = "iam.roles.update";
    public const string DeleteCustomRole = "iam.roles.delete";

    // Principal management
    public const string CreatePrincipal = "iam.principals.create";
    public const string GetPrincipal = "iam.principals.get";
    public const string UpdatePrincipal = "iam.principals.update";
    public const string DeletePrincipal = "iam.principals.delete";

    // Role binding management
    public const string GrantRole = "iam.bindings.grant";
    public const string RevokeRole = "iam.bindings.revoke";
    public const string ListBindings = "iam.bindings.list";

    // Permission resolution
    public const string CheckPermission = "iam.permissions.check";
    public const string BatchCheckPermissions = "iam.permissions.batch-check";
    public const string GetEffectivePermissions = "iam.permissions.effective";

    // Service account management
    public const string CreateServiceAccount = "iam.service-accounts.create";
    public const string GenerateApiKey = "iam.service-accounts.generate-key";
    public const string RevokeApiKey = "iam.service-accounts.revoke-key";
    public const string RotateApiKey = "iam.service-accounts.rotate-key";

    // Token issuance
    public const string IssueToken = "iam.tokens.issue";
    public const string RefreshToken = "iam.tokens.refresh";

    // Audit logs
    public const string ViewAuditLogs = "iam.audit.view";
}
