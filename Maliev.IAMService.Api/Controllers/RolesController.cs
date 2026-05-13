using Asp.Versioning;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.IAMService.Domain.Constants;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.Services;
using Microsoft.AspNetCore.Mvc;

namespace Maliev.IAMService.Api.Controllers;

/// <summary>
/// Controller for managing roles and their associated permissions.
/// Roles are collections of permissions that can be assigned to principals for access control.
/// Supports both built-in roles (registered by services) and custom user-defined roles.
/// </summary>
[ApiController]
[ApiVersion("1")]
[Route("iam/v{version:apiVersion}/roles")]
public class RolesController : ControllerBase
{
    private readonly IRoleService _roleService;
    private readonly ILogger<RolesController> _logger;

    /// <summary>
    /// Initializes a new instance of the RolesController class.
    /// </summary>
    /// <param name="roleService">Service for managing roles and their operations.</param>
    /// <param name="logger">Logger instance for recording diagnostic information.</param>
    public RolesController(IRoleService roleService, ILogger<RolesController> logger)
    {
        _roleService = roleService;
        _logger = logger;
    }

    /// <summary>
    /// Registers built-in roles for a service along with their associated permissions.
    /// </summary>
    /// <remarks>
    /// Built-in roles are predefined by services and are generally immutable after registration.
    /// Each role must include a list of existing permission identifiers (e.g., `supplier.suppliers.read`).
    ///
    /// **Security:** This endpoint requires authorization to ensure only Maliev services can register roles.
    /// </remarks>
    /// <param name="request">Role registration request containing service name and role definitions with permission mappings.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>Registered roles with their permission associations.</returns>
    /// <response code="200">Returns the registered role details.</response>
    /// <response code="400">If the role format is invalid or references non-existent permissions.</response>
    [HttpPost("register")]
    [RequirePermission(IAMPermissions.RolesCreate)]
    public async Task<IActionResult> RegisterRoles([FromBody] RegisterRolesRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var roles = await _roleService.RegisterRolesAsync(request, cancellationToken);
            return Ok(roles);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Retrieves roles with optional filtering by service name.
    /// </summary>
    /// <remarks>
    /// Returns all roles (built-in and custom). If `serviceName` is provided, filters to roles owned by that service.
    /// Requires explicit role list access.
    /// </remarks>
    /// <param name="serviceName">Optional filter to retrieve roles for a specific service.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>List of roles, optionally filtered by service.</returns>
    /// <response code="200">Returns the requested roles.</response>
    /// <response code="403">If the user lacks permission and system is already bootstrapped.</response>
    [HttpGet]
    [RequirePermission(IAMPermissions.RolesList)]
    public async Task<IActionResult> GetRoles([FromQuery] string? serviceName, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(serviceName))
        {
            var roles = await _roleService.GetByServiceAsync(serviceName, cancellationToken);
            return Ok(roles);
        }

        var allRoles = await _roleService.GetAllAsync(cancellationToken);
        return Ok(allRoles);
    }


    /// <summary>
    /// Retrieves a single role by its unique identifier.
    /// </summary>
    /// <remarks>
    /// Fetches full details including the list of associated permission identifiers.
    /// Requires explicit role read access.
    /// </remarks>
    /// <param name="roleId">The unique identifier of the role (e.g., `roles.supplier.admin`).</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>The requested role with its permissions.</returns>
    /// <response code="200">Returns the role details.</response>
    /// <response code="403">If the user lacks permission and system is already bootstrapped.</response>
    /// <response code="404">If the role ID is not found.</response>
    [HttpGet("{**roleId}")]
    [RequirePermission(IAMPermissions.RolesRead)]
    public async Task<IActionResult> GetRoleById(string roleId, CancellationToken cancellationToken)
    {
        var role = await _roleService.GetByIdAsync(roleId, cancellationToken);
        if (role == null)
        {
            return NotFound(new { error = $"Role {roleId} not found" });
        }
        return Ok(role);
    }


    /// <summary>
    /// Creates a new custom role.
    /// </summary>
    /// <remarks>
    /// Custom roles are user-defined and can include any combination of registered permissions.
    /// Unlike built-in roles, custom roles can be modified or deleted.
    /// </remarks>
    /// <param name="request">Custom role creation request containing role name and permission identifiers.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>Created custom role details.</returns>
    /// <response code="201">Returns the created custom role.</response>
    /// <response code="400">If validation fails or permissions don't exist.</response>
    /// <response code="403">If the user lacks `iam.roles.create` permission.</response>
    [HttpPost]
    [RequirePermission(IAMPermissions.RolesCreate)]
    public async Task<IActionResult> CreateCustomRole([FromBody] CreateCustomRoleRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var role = await _roleService.CreateCustomRoleAsync(request, cancellationToken);
            return CreatedAtAction(nameof(GetRoles), new { serviceName = role.ServiceName }, role);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Updates an existing custom role.
    /// </summary>
    /// <remarks>
    /// Allows updating the description and the set of associated permissions.
    /// Predefined roles CANNOT be updated via this endpoint.
    /// </remarks>
    /// <param name="roleId">The identifier of the custom role to update.</param>
    /// <param name="request">Update role request containing new permissions.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Updated role details.</returns>
    /// <response code="200">Returns the updated role.</response>
    /// <response code="400">If attempting to update a built-in role.</response>
    /// <response code="403">If the user lacks `iam.roles.update` permission.</response>
    /// <response code="404">If the role is not found.</response>
    [HttpPut("{**roleId}")]
    [RequirePermission(IAMPermissions.RolesUpdate)]
    public async Task<IActionResult> UpdateRole(string roleId, [FromBody] UpdateRoleRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var role = await _roleService.UpdateRoleAsync(roleId, request, cancellationToken);
            return Ok(role);
        }
        catch (InvalidOperationException ex)
        {
            // Distinguish between NotFound and BadRequest based on exception message
            if (ex.Message.Contains("not found"))
            {
                return NotFound(new { error = ex.Message });
            }
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Deletes an existing custom role.
    /// </summary>
    /// <remarks>
    /// Only custom roles can be deleted. Fails if the role is currently assigned to any principals.
    /// </remarks>
    /// <param name="roleId">The identifier of the custom role to delete.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>No content on success.</returns>
    /// <response code="204">If successfully deleted.</response>
    /// <response code="400">If role has active bindings or is predefined.</response>
    /// <response code="403">If the user lacks `iam.roles.delete` permission.</response>
    [HttpDelete("{**roleId}")]
    [RequirePermission(IAMPermissions.RolesDelete)]
    public async Task<IActionResult> DeleteRole(string roleId, CancellationToken cancellationToken)
    {
        try
        {
            await _roleService.DeleteRoleAsync(roleId, cancellationToken);
            return NoContent();
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }
}
