namespace Maliev.IAMService.Api.Authorization;

/// <summary>
/// IAM Service permission constants for internal authorization
/// </summary>
public static class Permissions
{
    /// <summary>
    /// Service name for IAM permissions.
    /// </summary>
    public const string ServiceName = "iam";

    // Permission management
    /// <summary>
    /// Permission to register permissions.
    /// </summary>
    public const string RegisterPermissions = "iam.permissions.register";
    /// <summary>
    /// Permission to list permissions.
    /// </summary>
    public const string ListPermissions = "iam.permissions.list";

    // Role management
    /// <summary>
    /// Permission to register roles.
    /// </summary>
    public const string RegisterRoles = "iam.roles.register";
    /// <summary>
    /// Permission to list roles.
    /// </summary>
    public const string ListRoles = "iam.roles.list";
    /// <summary>
    /// Permission to create a custom role.
    /// </summary>
    public const string CreateCustomRole = "iam.roles.create";
    /// <summary>
    /// Permission to update a custom role.
    /// </summary>
    public const string UpdateCustomRole = "iam.roles.update";
    /// <summary>
    /// Permission to delete a custom role.
    /// </summary>
    public const string DeleteCustomRole = "iam.roles.delete";

    // Principal management
    /// <summary>
    /// Permission to create a principal.
    /// </summary>
    public const string CreatePrincipal = "iam.principals.create";
    /// <summary>
    /// Permission to get principal details.
    /// </summary>
    public const string GetPrincipal = "iam.principals.get";
    /// <summary>
    /// Permission to update a principal.
    /// </summary>
    public const string UpdatePrincipal = "iam.principals.update";
    /// <summary>
    /// Permission to delete a principal.
    /// </summary>
    public const string DeletePrincipal = "iam.principals.delete";

    // Role binding management
    /// <summary>
    /// Permission to grant a role.
    /// </summary>
    public const string GrantRole = "iam.bindings.grant";
    /// <summary>
    /// Permission to revoke a role.
    /// </summary>
    public const string RevokeRole = "iam.bindings.revoke";
    /// <summary>
    /// Permission to list role bindings.
    /// </summary>
    public const string ListBindings = "iam.bindings.list";

    // Permission resolution
    /// <summary>
    /// Permission to check a specific permission.
    /// </summary>
    public const string CheckPermission = "iam.permissions.check";
    /// <summary>
    /// Permission to check multiple permissions in a batch.
    /// </summary>
    public const string BatchCheckPermissions = "iam.permissions.batch-check";
    /// <summary>
    /// Permission to get effective permissions.
    /// </summary>
    public const string GetEffectivePermissions = "iam.permissions.effective";

    // Service account management
    /// <summary>
    /// Permission to create a service account.
    /// </summary>
    public const string CreateServiceAccount = "iam.service-accounts.create";
    /// <summary>
    /// Permission to generate an API key for a service account.
    /// </summary>
    public const string GenerateApiKey = "iam.service-accounts.generate-key";
    /// <summary>
    /// Permission to revoke an API key from a service account.
    /// </summary>
    public const string RevokeApiKey = "iam.service-accounts.revoke-key";
    /// <summary>
    /// Permission to rotate an API key for a service account.
    /// </summary>
    public const string RotateApiKey = "iam.service-accounts.rotate-key";

    // Token issuance
    /// <summary>
    /// Permission to issue a token.
    /// </summary>
    public const string IssueToken = "iam.tokens.issue";
    /// <summary>
    /// Permission to refresh a token.
    /// </summary>
    public const string RefreshToken = "iam.tokens.refresh";

    // Audit logs
    /// <summary>
    /// Permission to view audit logs.
    /// </summary>
    public const string ViewAuditLogs = "iam.audit.view";
}
