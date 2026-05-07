using Asp.Versioning;
using Microsoft.EntityFrameworkCore;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.IAMService.Domain.Constants;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Application.Services;
using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Maliev.IAMService.Api.Controllers;

/// <summary>
/// Controller for managing principals (users and service accounts) and their role assignments.
/// Principals are the entities that receive permissions through roles or direct bindings.
/// Supports both human users and automated service accounts.
/// </summary>
[ApiController]
[ApiVersion("1")]
[Route("iam/v{version:apiVersion}/principals")]
public class PrincipalsController : ControllerBase
{
    private const string AspireTestAdminLinkedService = "AspireTestAdminSeeder";
    private readonly IPrincipalService _principalService;
    private readonly ILogger<PrincipalsController> _logger;

    /// <summary>
    /// Initializes a new instance of the PrincipalsController class.
    /// </summary>
    /// <param name="principalService">Service for managing principal operations and metadata.</param>
    /// <param name="logger">Logger instance for recording diagnostic information.</param>
    public PrincipalsController(IPrincipalService principalService, ILogger<PrincipalsController> logger)
    {
        _principalService = principalService;
        _logger = logger;
    }

    /// <summary>
    /// Retrieves all principals in the system.
    /// </summary>
    /// <remarks>
    /// Returns a list of all users and service accounts.
    /// Supports Development Bootstrap: allows access if system has 1 or fewer users.
    /// </remarks>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of principal summaries.</returns>
    [HttpGet]
    public async Task<IActionResult> GetPrincipals(CancellationToken cancellationToken)
    {
        // 1. Development Bootstrap: Check if we should allow access regardless of permissions
        var principals = await _principalService.GetPrincipalsAsync(cancellationToken);

        if (principals.Count() > 1)
        {
            // 2. Standard Path: Check for iam.principals.list permission
            var authorizationService = HttpContext.RequestServices.GetRequiredService<IAuthorizationService>();
            var authResult = await authorizationService.AuthorizeAsync(User, null, "Permission:" + IAMPermissions.PrincipalsList);

            if (!authResult.Succeeded)
            {
                return Forbid();
            }
        }

        return Ok(principals);
    }

    /// <summary>
    /// Retrieves a single principal by its unique identifier.
    /// </summary>
    /// <remarks>
    /// Supports Development Bootstrap: allows access if system has 1 or fewer users.
    /// </remarks>
    /// <param name="id">The unique identifier of the principal.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Principal details.</returns>
    [HttpGet("{id}")]
    public async Task<IActionResult> GetPrincipalById(Guid id, CancellationToken cancellationToken)
    {
        // 1. Development Bootstrap: Check if we should allow access regardless of permissions
        var principals = await _principalService.GetPrincipalsAsync(cancellationToken);

        if (principals.Count() > 1)
        {
            // 2. Standard Path: Check for iam.principals.read permission
            var authorizationService = HttpContext.RequestServices.GetRequiredService<IAuthorizationService>();
            var authResult = await authorizationService.AuthorizeAsync(User, null, "Permission:" + IAMPermissions.PrincipalsRead);

            if (!authResult.Succeeded)
            {
                return Forbid();
            }
        }

        var principal = await _principalService.GetByIdAsync(id, cancellationToken);
        if (principal == null)
        {
            return NotFound(new { error = $"Principal {id} not found" });
        }

        var response = new PrincipalResponse
        {
            PrincipalId = principal.PrincipalId,
            PrincipalType = principal.PrincipalType,
            Email = principal.Email,
            DisplayName = principal.DisplayName,
            LinkedService = principal.LinkedService,
            LinkedEntityId = principal.LinkedEntityId,
            IsActive = principal.IsActive,
            CreatedAt = principal.CreatedAt,
            UpdatedAt = principal.UpdatedAt
        };

        return Ok(response);
    }

    /// <summary>
    /// Retrieves a single principal by its email address.
    /// </summary>
    /// <param name="email">The email address of the principal.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Principal details.</returns>
    [HttpGet("by-email/{email}")]
    public async Task<IActionResult> GetPrincipalByEmail(string email, CancellationToken cancellationToken)
    {
        // 1. Development Bootstrap: Check if we should allow access regardless of permissions
        var principals = await _principalService.GetPrincipalsAsync(cancellationToken);

        if (principals.Count() > 1)
        {
            // 2. Standard Path: Check for iam.principals.read permission
            var authorizationService = HttpContext.RequestServices.GetRequiredService<IAuthorizationService>();
            var authResult = await authorizationService.AuthorizeAsync(User, null, "Permission:" + IAMPermissions.PrincipalsRead);

            if (!authResult.Succeeded)
            {
                return Forbid();
            }
        }

        var principal = await _principalService.GetByEmailAsync(email, cancellationToken);
        if (principal == null)
        {
            return NotFound(new { error = $"Principal with email {email} not found" });
        }

        var response = new PrincipalResponse
        {
            PrincipalId = principal.PrincipalId,
            PrincipalType = principal.PrincipalType,
            Email = principal.Email,
            DisplayName = principal.DisplayName,
            LinkedService = principal.LinkedService,
            LinkedEntityId = principal.LinkedEntityId,
            IsActive = principal.IsActive,
            CreatedAt = principal.CreatedAt,
            UpdatedAt = principal.UpdatedAt
        };

        return Ok(response);
    }

    /// <summary>
    /// Creates a new principal (user or service account).
    /// </summary>
    /// <param name="request">Principal creation request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Created principal response.</returns>
    [HttpPost]
    [RequirePermission(IAMPermissions.PrincipalsCreate)]
    public async Task<IActionResult> CreatePrincipal([FromBody] CreatePrincipalRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var principal = await _principalService.CreateAsync(
                request.PrincipalType,
                request.Email,
                request.LinkedService,
                request.LinkedEntityId,
                cancellationToken);

            // Update display name if provided
            if (!string.IsNullOrWhiteSpace(request.DisplayName))
            {
                principal.DisplayName = request.DisplayName;
                await _principalService.UpdateAsync(principal, cancellationToken);
            }

            var response = new CreatePrincipalResponse
            {
                PrincipalId = principal.PrincipalId,
                CreatedAt = principal.CreatedAt
            };

            return CreatedAtAction(nameof(GetPrincipalById), new { id = principal.PrincipalId }, response);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Failed to create principal: {Message}", ex.Message);
            return BadRequest(new { error = ex.Message });
        }
        catch (ArgumentException ex)
        {
            _logger.LogWarning(ex, "Invalid argument for principal creation: {Message}", ex.Message);
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Deletes a principal and all its associated bindings.
    /// </summary>
    /// <param name="id">The unique identifier of the principal to delete.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>No content on success.</returns>
    [HttpDelete("{id}")]
    [RequirePermission(IAMPermissions.PrincipalsDelete)]
    public async Task<IActionResult> DeletePrincipal(Guid id, CancellationToken cancellationToken)
    {
        await _principalService.DeleteAsync(id, cancellationToken);
        return NoContent();
    }

    /// <summary>
    /// Grants a role to a principal.
    /// Used by AuthService during auto-provisioning of the first @maliev.com employee
    /// to synchronously assign the Platform Owner role before issuing the JWT.
    /// </summary>
    /// <param name="id">The unique identifier of the principal.</param>
    /// <param name="request">The role grant request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>No content on success.</returns>
    [HttpPost("{id:guid}/roles")]
    [RequirePermission(IAMPermissions.BindingsCreate)]
    public async Task<IActionResult> GrantRole(Guid id, [FromBody] GrantRoleRequest request, CancellationToken cancellationToken)
    {
        var bindingService = HttpContext.RequestServices.GetRequiredService<IBindingService>();

        try
        {
            await bindingService.GrantRoleAsync(id, request, IAMDbContext.SystemPrincipalId, cancellationToken);
            _logger.LogInformation("Granted role {RoleId} to principal {PrincipalId}", request.RoleId, id);
            return NoContent();
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("already exists", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation("Role binding already exists for principal {PrincipalId} and role {RoleId}. Ignoring.", id, request.RoleId);
            return NoContent();
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("not found", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Principal or role not found when granting role {RoleId} to principal {PrincipalId}: {Message}", request.RoleId, id, ex.Message);
            return NotFound(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Gets the bootstrap status of the IAM system.
    /// Returns the total count of principals. Used by BFF for first-user detection.
    /// </summary>
    [HttpGet("bootstrap/status")]
    [AllowAnonymous]
    public async Task<IActionResult> GetBootstrapStatus(CancellationToken cancellationToken)
    {
        var principals = await _principalService.GetPrincipalsAsync(cancellationToken);
        var humanUsers = principals
            .Where(p => p.PrincipalType == "user" && p.LinkedService != AspireTestAdminLinkedService)
            .ToList();
        return Ok(new { Count = humanUsers.Count });
    }

    /// <summary>
    /// Promotes the currently authenticated user to Platform Owner.
    /// Only succeeds if no human user (PrincipalType == "user") already holds roles.platform.owner.
    /// </summary>
    /// <remarks>
    /// Called by IntranetBff's OnTicketReceived handler after every first login attempt.
    /// Returns 200 OK when this call grants the role, or 400 BadRequest when the
    /// EmployeeCreatedConsumer already did so via RabbitMQ (bootstrap race).
    ///
    /// ⚠ IntranetBff MUST re-exchange the token on BOTH 200 and 400 — the JWT present in the
    /// cookie at callback time was issued before the role was granted, so it carries zero
    /// permissions regardless of which path wins the race.  See IntranetBff/Program.cs
    /// OnTicketReceived for the matching comment.
    ///
    /// ⚠ SYSTEM PRINCIPAL FILTER — the join on PrincipalType == "user" is NOT optional.
    /// PrincipalService auto-grants roles.platform.owner to every "system" service principal
    /// at startup.  Without this filter, those bindings would make platformOwnerExists = true
    /// and this endpoint would always return 400 even on a fresh DB, preventing the first
    /// human user from ever gaining permissions.
    /// </remarks>
    [HttpPost("bootstrap/promote")]
    public async Task<IActionResult> PromoteCallerToAdmin(CancellationToken cancellationToken)
    {
        var iamDb = HttpContext.RequestServices.GetRequiredService<IAMDbContext>();

        var userIdClaim = User.FindFirst("sub")?.Value ?? User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim))
        {
            return Unauthorized(new { error = "Valid principal ID not found in token." });
        }

        Guid.TryParse(userIdClaim, out var principalId);
        var callerEmail = User.FindFirst("email")?.Value;

        var principalRepo = HttpContext.RequestServices.GetRequiredService<IPrincipalRepository>();
        var callerPrincipal = principalId != Guid.Empty
            ? await principalRepo.GetByIdAsync(principalId, cancellationToken)
            : (!string.IsNullOrEmpty(callerEmail) ? await principalRepo.GetByEmailAsync(callerEmail, cancellationToken) : null);

        if (callerPrincipal != null)
        {
            var callerHasRole = await iamDb.PrincipalRoleBindings
                .AnyAsync(b => b.PrincipalId == callerPrincipal.PrincipalId && b.RoleId == "roles.platform.owner", cancellationToken);

            if (callerHasRole)
            {
                return Ok(new { message = "Already promoted." });
            }
        }

        var platformOwnerExists = await (
            from b in iamDb.PrincipalRoleBindings
            join p in iamDb.Principals on b.PrincipalId equals p.PrincipalId
            where b.RoleId == "roles.platform.owner" &&
                  p.PrincipalType == "user" &&
                  p.LinkedService != AspireTestAdminLinkedService
            select b.BindingId
        ).AnyAsync(cancellationToken);

        if (platformOwnerExists)
        {
            return BadRequest(new { error = "System is already bootstrapped." });
        }

        await BootstrapAdminRoleAsync(principalId, cancellationToken);

        return Ok(new { message = "Successfully promoted to IAM Administrator." });
    }

    private async Task BootstrapAdminRoleAsync(Guid principalId, CancellationToken ct)
    {
        // Resolve services from request scope
        var principalRepo = HttpContext.RequestServices.GetRequiredService<IPrincipalRepository>();
        var roleRepo = HttpContext.RequestServices.GetRequiredService<IRoleRepository>();
        var bindingService = HttpContext.RequestServices.GetRequiredService<IBindingService>();

        var email = User.FindFirst("email")?.Value ?? "admin@maliev.com";
        var name = User.FindFirst("name")?.Value ?? "System Admin";

        // 1. Ensure Principal exists (Idempotent creation for bootstrap)
        // If principalId is Guid.Empty (Google SSO pre-IAM bootstrap), look up by email first.
        var principal = principalId != Guid.Empty
            ? await principalRepo.GetByIdAsync(principalId, ct)
            : await principalRepo.GetByEmailAsync(email, ct);

        if (principal == null)
        {
            _logger.LogInformation("Creating principal {PrincipalId} during bootstrap promotion.", principalId);

            // Assign a real GUID when principalId is Guid.Empty (Google SSO pre-IAM bootstrap)
            var effectivePrincipalId = principalId != Guid.Empty ? principalId : Guid.NewGuid();

            principal = new Principal
            {
                PrincipalId = effectivePrincipalId,
                Email = email,
                DisplayName = name,
                PrincipalType = "user",
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            try
            {
                await principalRepo.CreateAsync(principal, ct);
            }
            catch (Microsoft.EntityFrameworkCore.DbUpdateException ex) when (ex.InnerException is Npgsql.PostgresException { SqlState: "23505" })
            {
                // IX_principals_email fired — principal with this email already exists.
                // Fall back to lookup by email (may have a different PrincipalId assigned by another process).
                _logger.LogInformation("Principal with email {Email} already exists, looking up by email.", email);
                principal = await principalRepo.GetByEmailAsync(email, ct);
            }
        }

        if (principal == null)
        {
            _logger.LogWarning("Principal {PrincipalId} still not found after creation attempt. Aborting promotion.", principalId);
            return;
        }

        const string adminRoleId = "roles.platform.owner";

        // Use the resolved principal ID (may differ from original principalId if it was Guid.Empty)
        var resolvedPrincipalId = principal.PrincipalId;

        // Use BindingService to get existing bindings (handles expiry)
        var existingBindings = await bindingService.GetBindingsAsync(resolvedPrincipalId, ct);
        if (existingBindings.Any(b => b.RoleId == adminRoleId && (string.IsNullOrEmpty(b.ResourcePath) || b.ResourcePath == "*")))
        {
            _logger.LogInformation("Principal {PrincipalId} already has the {RoleId} role. Skipping promotion.", resolvedPrincipalId, adminRoleId);
            return;
        }

        // 2. Ensure Role exists
        var adminRole = await roleRepo.GetByIdAsync(adminRoleId, ct);
        if (adminRole == null)
        {
            _logger.LogInformation("Creating {RoleId} role as it does not exist", adminRoleId);
            adminRole = new Role
            {
                RoleId = adminRoleId,
                RoleName = "Platform Owner",
                ServiceName = "platform",
                Description = "Full ownership and administrative access to all platform services and resources",
                IsCustom = false,
                CreatedBy = IAMDbContext.SystemPrincipalId,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                RolePermissions = new List<RolePermission>
                {
                    new RolePermission { RoleId = adminRoleId, PermissionId = "*" }
                }
            };

            try
            {
                await roleRepo.CreateAsync(adminRole, ct);
            }
            catch (Microsoft.EntityFrameworkCore.DbUpdateException ex) when (ex.InnerException is Npgsql.PostgresException { SqlState: "23505" })
            {
                _logger.LogInformation("Role {RoleId} already exists.", adminRoleId);
            }
        }

        // 3. Grant Role using BindingService (handles cache invalidation and events)
        try
        {
            await bindingService.GrantRoleAsync(resolvedPrincipalId, new GrantRoleRequest
            {
                RoleId = adminRoleId,
                ResourcePath = "*"
            }, IAMDbContext.SystemPrincipalId, ct);

            _logger.LogInformation("Successfully promoted principal {PrincipalId} to {RoleId}", resolvedPrincipalId, adminRoleId);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("already exists"))
        {
            _logger.LogInformation("Binding already exists for {PrincipalId} and {RoleId}", resolvedPrincipalId, adminRoleId);
        }
    }
}
