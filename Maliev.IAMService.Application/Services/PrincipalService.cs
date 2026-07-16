using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Application.Workloads;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;

namespace Maliev.IAMService.Application.Services;

/// <summary>
/// Service for managing principals (users and service accounts) with support for API key generation and rotation.
/// Handles principal lifecycle, service account API keys with PBKDF2 hashing (100,000 iterations, HMACSHA256),
/// and effective permission queries with 5-minute caching.
/// </summary>
public interface IPrincipalService
{
    /// <summary>
    /// Retrieves a principal by its unique identifier.
    /// </summary>
    /// <param name="principalId">The principal ID to look up.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Principal entity if found; otherwise null.</returns>
    Task<Principal?> GetByIdAsync(Guid principalId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a principal by email address.
    /// </summary>
    /// <param name="email">The email address to search for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Principal entity if found; otherwise null.</returns>
    Task<Principal?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a principal linked to an external service entity.
    /// </summary>
    /// <param name="linkedService">The external service name.</param>
    /// <param name="linkedEntityId">The entity ID in the external service.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Principal entity if found; otherwise null.</returns>
    Task<Principal?> GetByLinkedEntityAsync(string linkedService, Guid linkedEntityId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new principal (user or service account).
    /// </summary>
    /// <param name="principalType">Type of principal: "user" or "service_account".</param>
    /// <param name="email">Email address (required for users).</param>
    /// <param name="linkedService">External service name for linked principals.</param>
    /// <param name="linkedEntityId">External entity ID for linked principals.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Created principal entity.</returns>
    Task<Principal> CreateAsync(string principalType, string? email, string? linkedService, Guid? linkedEntityId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing principal entity.
    /// </summary>
    /// <param name="principal">Principal entity with updated values.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task UpdateAsync(Principal principal, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a principal by ID.
    /// </summary>
    /// <param name="principalId">The principal ID to delete.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task DeleteAsync(Guid principalId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a service account principal with a cryptographically secure API key.
    /// </summary>
    /// <param name="request">Service account creation request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Service account response with the plaintext API key (only returned once on creation).</returns>
    Task<ServiceAccountResponse> CreateServiceAccountAsync(CreateServiceAccountRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Rotates the API key for a service account.
    /// </summary>
    /// <param name="principalId">The service account principal ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Response with new API key (only shown once).</returns>
    Task<RotateApiKeyResponse> RotateApiKeyAsync(Guid principalId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all service accounts in the system.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of service account summaries.</returns>
    Task<IEnumerable<ServiceAccountResponse>> GetServiceAccountsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all principals in the system.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of all principals.</returns>
    Task<IEnumerable<PrincipalResponse>> GetPrincipalsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets effective permissions with deduplicated permissions and role attribution.
    /// </summary>
    /// <param name="principalId">The principal ID.</param>
    /// <param name="resourcePath">Optional resource path scope.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Effective permissions response.</returns>
    Task<EffectivePermissionsResponse> GetEffectivePermissionsAsync(Guid principalId, string? resourcePath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves a principal identifier (GUID, email, or service name) to a unique GUID.
    /// </summary>
    /// <param name="principalId">The principal identifier to resolve.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The resolved unique GUID of the principal.</returns>
    Task<Guid> ResolvePrincipalIdAsync(string principalId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Implementation of principal service with secure API key management using PBKDF2 hashing.
/// </summary>
public class PrincipalService : IPrincipalService
{
    private readonly IPrincipalRepository _principalRepository;
    private readonly IServiceAccountApiKeyRepository _apiKeyRepository;
    private readonly IBindingRepository _bindingRepository;
    private readonly IRoleRepository _roleRepository;
    private readonly IPermissionRepository _permissionRepository;
    private readonly ICacheService _cacheService;
    private readonly IAuditService _auditService;
    private readonly ILogger<PrincipalService> _logger;
    private readonly IConfiguration _configuration;

    /// <summary>
    /// Initializes a new instance of the <see cref="PrincipalService"/> class.
    /// </summary>
    /// <param name="principalRepository">The principal repository.</param>
    /// <param name="apiKeyRepository">The service account API key repository.</param>
    /// <param name="bindingRepository">The binding repository.</param>
    /// <param name="roleRepository">The role repository.</param>
    /// <param name="permissionRepository">The permission repository.</param>
    /// <param name="cacheService">The cache service.</param>
    /// <param name="auditService">The audit service.</param>
    /// <param name="configuration">The configuration.</param>
    /// <param name="logger">The logger.</param>
    public PrincipalService(
        IPrincipalRepository principalRepository,
        IServiceAccountApiKeyRepository apiKeyRepository,
        IBindingRepository bindingRepository,
        IRoleRepository roleRepository,
        IPermissionRepository permissionRepository,
        ICacheService cacheService,
        IAuditService auditService,
        IConfiguration configuration,
        ILogger<PrincipalService> logger)
    {
        _principalRepository = principalRepository;
        _apiKeyRepository = apiKeyRepository;
        _bindingRepository = bindingRepository;
        _roleRepository = roleRepository;
        _permissionRepository = permissionRepository;
        _cacheService = cacheService;
        _auditService = auditService;
        _configuration = configuration;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<Guid> ResolvePrincipalIdAsync(string principalId, CancellationToken cancellationToken = default)
    {
        if (Guid.TryParse(principalId, out var guid))
        {
            return guid;
        }

        var cacheKey = $"iam:principal_resolution:{principalId.ToLowerInvariant()}";
        var cachedGuid = await _cacheService.GetAsync<Guid?>(cacheKey, cancellationToken);
        if (cachedGuid.HasValue)
        {
            return cachedGuid.Value;
        }

        var principal = await _principalRepository.GetByEmailAsync(principalId, cancellationToken);
        if (principal == null)
        {
            var serviceEmail = $"{principalId.ToLowerInvariant()}@serviceaccount.maliev.local";
            principal = await _principalRepository.GetByEmailAsync(serviceEmail, cancellationToken);
        }

        if (principal == null)
        {
            _logger.LogWarning("Rejected unresolved principal identifier {PrincipalId}", principalId);
            throw new InvalidOperationException($"Principal '{principalId}' could not be resolved to a GUID.");
        }

        await _cacheService.SetAsync(cacheKey, principal.PrincipalId, TimeSpan.FromHours(1), cancellationToken);

        return principal.PrincipalId;
    }

    /// <inheritdoc />
    public async Task<Principal?> GetByIdAsync(Guid principalId, CancellationToken cancellationToken = default)
    {
        return await _principalRepository.GetByIdAsync(principalId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<Principal?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("Email cannot be empty", nameof(email));

        return await _principalRepository.GetByEmailAsync(email, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<Principal?> GetByLinkedEntityAsync(string linkedService, Guid linkedEntityId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(linkedService))
            throw new ArgumentException("Linked service cannot be empty", nameof(linkedService));

        return await _principalRepository.GetByLinkedEntityAsync(linkedService, linkedEntityId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<Principal> CreateAsync(string principalType, string? email, string? linkedService, Guid? linkedEntityId, CancellationToken cancellationToken = default)
    {
        if (principalType != "user" && principalType != "service_account")
            throw new ArgumentException("Principal type must be 'user' or 'service_account'", nameof(principalType));

        if (principalType == "user" && string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("Email is required for user principals", nameof(email));

        if (!string.IsNullOrWhiteSpace(email))
        {
            var existing = await _principalRepository.GetByEmailAsync(email, cancellationToken);
            if (existing != null)
                throw new InvalidOperationException($"Principal with email {email} already exists");
        }

        if (!string.IsNullOrWhiteSpace(linkedService) && linkedEntityId.HasValue)
        {
            var existing = await _principalRepository.GetByLinkedEntityAsync(linkedService, linkedEntityId.Value, cancellationToken);
            if (existing != null)
                throw new InvalidOperationException($"Principal for {linkedService}:{linkedEntityId} already exists");
        }

        var principal = new Principal
        {
            PrincipalId = Guid.NewGuid(),
            PrincipalType = principalType,
            Email = email,
            LinkedService = linkedService,
            LinkedEntityId = linkedEntityId,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        return await _principalRepository.CreateAsync(principal, cancellationToken);
    }

    /// <inheritdoc />
    public async Task UpdateAsync(Principal principal, CancellationToken cancellationToken = default)
    {
        principal.UpdatedAt = DateTime.UtcNow;
        await _principalRepository.UpdateAsync(principal, cancellationToken);
    }

    /// <inheritdoc />
    public async Task DeleteAsync(Guid principalId, CancellationToken cancellationToken = default)
    {
        var principal = await _principalRepository.GetByIdAsync(principalId, cancellationToken);
        if (principal?.WorkloadId is not null)
        {
            throw new ManagedWorkloadMutationException("Managed workload principals cannot be deleted through the generic principal API.");
        }

        await _principalRepository.DeleteAsync(principalId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<ServiceAccountResponse> CreateServiceAccountAsync(CreateServiceAccountRequest request, CancellationToken cancellationToken = default)
    {
        var email = $"{request.Name}@serviceaccount.maliev.local";
        var existingPrincipal = await _principalRepository.GetByEmailAsync(email, cancellationToken);
        if (existingPrincipal != null)
        {
            throw new InvalidOperationException($"Service account with name '{request.Name}' already exists");
        }

        var principal = new Principal
        {
            PrincipalId = Guid.NewGuid(),
            PrincipalType = "service_account",
            Email = email,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await _principalRepository.CreateAsync(principal, cancellationToken);

        var apiKey = GenerateApiKey();
        var apiKeyPrefix = apiKey.Substring(0, 8);

        var hashedKey = HashApiKey(apiKey);

        var serviceAccountKey = new ServiceAccountApiKey
        {
            KeyId = Guid.NewGuid(),
            PrincipalId = principal.PrincipalId,
            KeyHash = hashedKey,
            KeyPrefix = apiKeyPrefix,
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        await _apiKeyRepository.CreateAsync(serviceAccountKey, cancellationToken);

        await _auditService.LogAsync("CREATE_SERVICE_ACCOUNT", principal.PrincipalId, new Dictionary<string, object>
        {
            ["name"] = request.Name,
            ["principal_id"] = principal.PrincipalId
        }, cancellationToken);

        _logger.LogInformation("Created service account {Name} with principal ID {PrincipalId}", request.Name, principal.PrincipalId);

        return new ServiceAccountResponse
        {
            PrincipalId = principal.PrincipalId,
            Name = request.Name,
            Description = request.Description,
            ApiKey = apiKey,
            ApiKeyPrefix = apiKeyPrefix,
            CreatedAt = principal.CreatedAt
        };
    }

    /// <inheritdoc />
    public async Task<RotateApiKeyResponse> RotateApiKeyAsync(Guid principalId, CancellationToken cancellationToken = default)
    {
        var principal = await _principalRepository.GetByIdAsync(principalId, cancellationToken);
        if (principal == null)
            throw new InvalidOperationException($"Principal {principalId} not found");

        if (principal.PrincipalType != "service_account")
            throw new InvalidOperationException($"Principal {principalId} is not a service account");

        if (principal.WorkloadId is not null)
            throw new ManagedWorkloadMutationException("Managed workload principals cannot receive IAM API keys.");

        await _apiKeyRepository.DeactivateByPrincipalIdAsync(principalId, cancellationToken);

        var newApiKey = GenerateApiKey();
        var apiKeyPrefix = newApiKey.Substring(0, 8);
        var hashedKey = HashApiKey(newApiKey);

        var serviceAccountKey = new ServiceAccountApiKey
        {
            KeyId = Guid.NewGuid(),
            PrincipalId = principalId,
            KeyHash = hashedKey,
            KeyPrefix = apiKeyPrefix,
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        await _apiKeyRepository.CreateAsync(serviceAccountKey, cancellationToken);

        await _auditService.LogAsync("ROTATE_KEY", principalId, new Dictionary<string, object>
        {
            ["principal_id"] = principalId
        }, cancellationToken);

        _logger.LogInformation("Rotated API key for service account {PrincipalId}", principalId);

        return new RotateApiKeyResponse
        {
            PrincipalId = principalId,
            NewApiKey = newApiKey,
            ApiKeyPrefix = apiKeyPrefix,
            CreatedAt = DateTime.UtcNow
        };
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ServiceAccountResponse>> GetServiceAccountsAsync(CancellationToken cancellationToken = default)
    {
        var allPrincipals = await _principalRepository.GetAllAsync(cancellationToken);
        var serviceAccounts = allPrincipals.Where(p => p.PrincipalType == "service_account");

        var responses = new List<ServiceAccountResponse>();
        foreach (var sa in serviceAccounts)
        {
            var keys = await _apiKeyRepository.GetByPrincipalIdAsync(sa.PrincipalId, cancellationToken);
            var activeKey = keys.FirstOrDefault();

            responses.Add(new ServiceAccountResponse
            {
                PrincipalId = sa.PrincipalId,
                Name = sa.Email?.Split('@')[0] ?? "unknown",
                Description = null,
                ApiKeyPrefix = activeKey?.KeyPrefix,
                CreatedAt = sa.CreatedAt
            });
        }

        return responses;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<PrincipalResponse>> GetPrincipalsAsync(CancellationToken cancellationToken = default)
    {
        var principals = await _principalRepository.GetAllAsync(cancellationToken);
        return principals.Select(p => new PrincipalResponse
        {
            PrincipalId = p.PrincipalId,
            PrincipalType = p.PrincipalType,
            Email = p.Email,
            DisplayName = p.DisplayName,
            LinkedService = p.LinkedService,
            LinkedEntityId = p.LinkedEntityId,
            IsActive = p.IsActive,
            CreatedAt = p.CreatedAt,
            UpdatedAt = p.UpdatedAt
        });
    }

    /// <inheritdoc />
    public async Task<EffectivePermissionsResponse> GetEffectivePermissionsAsync(
        Guid principalId,
        string? resourcePath,
        CancellationToken cancellationToken = default)
    {
        var principal = await _principalRepository.GetByIdAsync(principalId, cancellationToken);
        if (principal == null)
            throw new InvalidOperationException($"Principal {principalId} not found");

        var cacheKey = IamPermissionCacheKeys.ForPermissions(principalId, resourcePath);

        var cached = await _cacheService.GetAsync<EffectivePermissionsResponse>(cacheKey, cancellationToken);
        if (cached != null)
        {
            _logger.LogDebug("Effective permissions cache hit for principal {PrincipalId}", principalId);
            return cached;
        }

        var bindings = await _bindingRepository.GetByPrincipalAsync(principalId, cancellationToken);

        var activeBindings = bindings.Where(b => !b.ExpiresAt.HasValue || b.ExpiresAt.Value > DateTime.UtcNow);

        activeBindings = activeBindings.Where(b =>
        {
            if (string.IsNullOrEmpty(b.ResourcePath) || b.ResourcePath == "*")
                return true;

            if (string.IsNullOrEmpty(resourcePath))
                return false;

            return MatchesResourcePath(b.ResourcePath, resourcePath);
        });

        var roleIds = activeBindings.Select(b => b.RoleId).Distinct().ToList();

        var roles = await _roleRepository.GetByIdsAsync(roleIds, cancellationToken);
        var allRolePermissions = await _roleRepository.GetPermissionsForRolesAsync(roleIds, cancellationToken);

        var rolesMap = roles.ToDictionary(r => r.RoleId);

        var permissionRoleMap = new Dictionary<string, HashSet<string>>();
        var permissionBindingMap = new Dictionary<string, List<string?>>();

        foreach (var roleId in roleIds)
        {
            if (!rolesMap.TryGetValue(roleId, out var role)) continue;

            var rolePermissions = allRolePermissions.Where(rp => rp.RoleId == roleId).Select(rp => rp.Permission);
            var relevantBindings = activeBindings.Where(b => b.RoleId == roleId);

            foreach (var permission in rolePermissions)
            {
                if (!permissionRoleMap.ContainsKey(permission.PermissionId))
                {
                    permissionRoleMap[permission.PermissionId] = new HashSet<string>();
                    permissionBindingMap[permission.PermissionId] = new List<string?>();
                }

                permissionRoleMap[permission.PermissionId].Add(roleId);

                foreach (var binding in relevantBindings)
                {
                    permissionBindingMap[permission.PermissionId].Add(binding.ResourcePath);
                }
            }
        }

        var uniquePermissionIds = permissionRoleMap.Keys.ToList();
        var permissionEntities = await _permissionRepository.GetByIdsAsync(uniquePermissionIds, cancellationToken);
        var permissionsMap = permissionEntities.ToDictionary(p => p.PermissionId);

        var effectivePermissions = new List<EffectivePermissionDto>();

        foreach (var permissionId in uniquePermissionIds)
        {
            if (!permissionsMap.TryGetValue(permissionId, out var permission)) continue;

            var grantedByRoleIds = permissionRoleMap[permissionId];
            var roleNames = new List<string>();
            foreach (var rId in grantedByRoleIds)
            {
                if (rolesMap.TryGetValue(rId, out var r))
                {
                    roleNames.Add(r.RoleName);
                }
            }

            var resourcePaths = permissionBindingMap[permissionId];
            var distinctPaths = resourcePaths.Where(p => !string.IsNullOrEmpty(p)).Distinct().Cast<string>().ToList();
            var isScoped = distinctPaths.Any();

            effectivePermissions.Add(new EffectivePermissionDto
            {
                PermissionId = permission.PermissionId,
                Description = permission.Description ?? "",
                GrantedByRoles = roleNames,
                ResourcePath = isScoped ? string.Join(", ", distinctPaths) : null,
                IsScoped = isScoped
            });
        }

        var response = new EffectivePermissionsResponse
        {
            PrincipalId = principalId,
            Permissions = effectivePermissions.OrderBy(p => p.PermissionId),
            QueriedAt = DateTime.UtcNow
        };

        await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(5), cancellationToken);

        _logger.LogInformation("Queried effective permissions for principal {PrincipalId}, found {Count} permissions",
            principalId, effectivePermissions.Count);

        return response;
    }

    /// <summary>
    /// Matches a binding's resource path against a requested resource path.
    /// </summary>
    /// <param name="bindingPath">Resource path from binding.</param>
    /// <param name="requestPath">Requested hierarchical path.</param>
    /// <returns>True if the binding matches the request.</returns>
    private bool MatchesResourcePath(string? bindingPath, string? requestPath)
    {
        if (string.IsNullOrEmpty(requestPath))
            return string.IsNullOrEmpty(bindingPath) || bindingPath == "*";

        if (string.IsNullOrEmpty(bindingPath))
            return false;

        if (bindingPath == "*")
            return true;

        if (requestPath == bindingPath || requestPath.StartsWith(bindingPath + "/"))
            return true;

        if (bindingPath.EndsWith("/**"))
        {
            var prefix = bindingPath[..^3];
            return requestPath.StartsWith(prefix + "/") || requestPath == prefix;
        }

        if (bindingPath.EndsWith("/*"))
        {
            var prefix = bindingPath[..^2];
            if (requestPath.StartsWith(prefix + "/"))
            {
                var remainder = requestPath[(prefix.Length + 1)..];
                return !remainder.Contains('/');
            }
        }

        return false;
    }

    /// <summary>
    /// Generates a cryptographically secure 44-character API key with 256-bit entropy.
    /// </summary>
    /// <returns>44-character API key string.</returns>
    private string GenerateApiKey()
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var result = new char[44];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = chars[RandomNumberGenerator.GetInt32(chars.Length)];
        }

        return new string(result);
    }

    /// <summary>
    /// Hashes an API key using PBKDF2 with HMACSHA256 (100,000 iterations, random 128-bit salt).
    /// Output format: "{base64Salt}:{base64Hash}".
    /// </summary>
    /// <param name="apiKey">The plaintext API key to hash.</param>
    /// <returns>Salted hash string in format "salt:hash" (both base64-encoded).</returns>
    private string HashApiKey(string apiKey)
    {
        byte[] salt = new byte[128 / 8];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: apiKey,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8));

        return $"{Convert.ToBase64String(salt)}:{hashed}";
    }
}
