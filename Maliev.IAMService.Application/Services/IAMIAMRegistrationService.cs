using Maliev.Aspire.ServiceDefaults.IAM;
using Maliev.IAMService.Application.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Maliev.IAMService.Application.Services;

/// <summary>
/// Registers IAM Service permissions and roles with the centralized IAM service on startup.
/// </summary>
public class IAMIAMRegistrationService(
    IConfiguration configuration,
    ILogger<IAMIAMRegistrationService> logger) : IAMRegistrationService(configuration, logger, "iam")
{
    /// <inheritdoc />
    protected override IEnumerable<PermissionRegistration> GetPermissions()
    {
        return IAMPermissions.AllWithDescriptions.Select(p => new PermissionRegistration
        {
            PermissionId = p.Key,
            Description = p.Value
        });
    }

    /// <inheritdoc />
    protected override IEnumerable<RoleRegistration> GetPredefinedRoles()
    {
        return IAMPredefinedRoles.All.Select(r => new RoleRegistration
        {
            RoleId = r.RoleId,
            Description = r.Description,
            PermissionIds = [.. r.Permissions],
            IsCustom = false
        });
    }
}
