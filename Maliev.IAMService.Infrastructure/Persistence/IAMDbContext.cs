using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Infrastructure.Persistence.Configurations;
using Microsoft.EntityFrameworkCore;

namespace Maliev.IAMService.Infrastructure.Persistence;

/// <summary>
/// Database context for the IAM Service.
/// </summary>
public class IAMDbContext : DbContext
{
    /// <summary>
    /// The well-known Guid used to identify the system principal for automated operations.
    /// </summary>
    public static readonly Guid SystemPrincipalId = new Guid("00000000-0000-0000-0000-000000000001");

    /// <summary>
    /// Initializes a new instance of the <see cref="IAMDbContext"/> class.
    /// </summary>
    /// <param name="options">The options for this context.</param>
    public IAMDbContext(DbContextOptions<IAMDbContext> options) : base(options)
    {
    }

    /// <summary>
    /// Gets or sets the Principals DbSet.
    /// </summary>
    public DbSet<Principal> Principals { get; set; } = null!;

    /// <summary>
    /// Gets or sets the Permissions DbSet.
    /// </summary>
    public DbSet<Permission> Permissions { get; set; } = null!;

    /// <summary>
    /// Gets or sets the Roles DbSet.
    /// </summary>
    public DbSet<Role> Roles { get; set; } = null!;

    /// <summary>
    /// Gets or sets the RolePermissions DbSet.
    /// </summary>
    public DbSet<RolePermission> RolePermissions { get; set; } = null!;

    /// <summary>
    /// Gets or sets the PrincipalRoleBindings DbSet.
    /// </summary>
    public DbSet<PrincipalRoleBinding> PrincipalRoleBindings { get; set; } = null!;

    /// <summary>
    /// Gets or sets the PrincipalPermissionBindings DbSet.
    /// </summary>
    public DbSet<PrincipalPermissionBinding> PrincipalPermissionBindings { get; set; } = null!;

    /// <summary>
    /// Gets or sets the ServiceAccountApiKeys DbSet.
    /// </summary>
    public DbSet<ServiceAccountApiKey> ServiceAccountApiKeys { get; set; } = null!;

    /// <summary>
    /// Gets or sets the IAMAuditLogs DbSet.
    /// </summary>
    public DbSet<IAMAuditLog> IAMAuditLogs { get; set; } = null!;

    /// <summary>
    /// Gets or sets idempotent workload provisioning operations.
    /// </summary>
    public DbSet<WorkloadProvisioningOperation> WorkloadProvisioningOperations { get; set; } = null!;

    /// <summary>
    /// Configures the model using the model builder.
    /// </summary>
    /// <param name="modelBuilder">The model builder instance.</param>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.UseSnakeCaseNaming();

        modelBuilder.Entity<RolePermission>()
            .HasKey(rp => new { rp.RoleId, rp.PermissionId });

        modelBuilder.Entity<Permission>()
            .HasIndex(p => p.PermissionId)
            .IsUnique();

        modelBuilder.Entity<Principal>()
            .HasIndex(p => p.Email)
            .IsUnique();

        modelBuilder.Entity<Principal>()
            .HasIndex(p => p.WorkloadId)
            .IsUnique()
            .HasFilter("workload_id IS NOT NULL");

        modelBuilder.Entity<Role>()
            .HasIndex(r => r.RoleId)
            .IsUnique();

        modelBuilder.Entity<PrincipalRoleBinding>()
            .HasIndex(prb => new { prb.PrincipalId, prb.RoleId, prb.ResourcePath })
            .IsUnique();

        modelBuilder.Entity<PrincipalPermissionBinding>()
            .HasIndex(ppb => new { ppb.PrincipalId, ppb.PermissionId, ppb.ResourcePath })
            .IsUnique();

        modelBuilder.Entity<Permission>()
            .HasIndex(p => p.ServiceName);

        modelBuilder.Entity<Permission>()
            .HasIndex(p => p.ResourceType);

        modelBuilder.Entity<Role>()
            .HasIndex(r => r.ServiceName);

        modelBuilder.Entity<Role>()
            .HasIndex(r => r.IsCustom);

        modelBuilder.Entity<PrincipalRoleBinding>()
            .HasIndex(prb => prb.PrincipalId);

        modelBuilder.Entity<PrincipalRoleBinding>()
            .HasIndex(prb => prb.RoleId);

        modelBuilder.Entity<PrincipalPermissionBinding>()
            .HasIndex(ppb => ppb.PrincipalId);

        modelBuilder.Entity<PrincipalPermissionBinding>()
            .HasIndex(ppb => ppb.PermissionId);

        modelBuilder.Entity<PrincipalRoleBinding>()
            .HasIndex(prb => prb.ExpiresAt)
            .HasFilter("expires_at IS NOT NULL");

        modelBuilder.Entity<ServiceAccountApiKey>()
            .HasIndex(sak => sak.PrincipalId);

        modelBuilder.Entity<ServiceAccountApiKey>()
            .HasIndex(sak => sak.KeyPrefix);

        modelBuilder.Entity<IAMAuditLog>()
            .HasIndex(al => al.PrincipalId);

        modelBuilder.Entity<IAMAuditLog>()
            .HasIndex(al => al.Action);

        modelBuilder.Entity<IAMAuditLog>()
            .HasIndex(al => al.Timestamp)
            .IsDescending();

        modelBuilder.Entity<IAMAuditLog>()
            .HasIndex(al => al.PerformedBy);

        modelBuilder.Entity<WorkloadProvisioningOperation>()
            .HasIndex(operation => new { operation.WorkloadId, operation.ProfileVersion });

        modelBuilder.Entity<Principal>()
            .ToTable(t =>
            {
                t.HasCheckConstraint("CK_Principal_Type", "principal_type IN ('user', 'service_account', 'system')");
                t.HasCheckConstraint(
                    "CK_Principal_WorkloadId",
                    "workload_id IS NULL OR workload_id ~ '^[a-z0-9]+(-[a-z0-9]+)*$'");
            });

        modelBuilder.Entity<Permission>()
            .ToTable(t => t.HasCheckConstraint("CK_Permission_Format", "permission_id = '*' OR permission_id ~ '^[a-z0-9-]+\\.[a-z0-9-]+\\.[a-z0-9-]+$'"));

        modelBuilder.Entity<Role>()
            .ToTable(t => t.HasCheckConstraint("CK_Role_Service", "(is_custom = TRUE) OR (service_name IS NOT NULL)"));

        modelBuilder.Entity<IAMAuditLog>()
            .ToTable(t => t.HasCheckConstraint("CK_AuditLog_Action",
                @"action IN ('GRANT_ROLE', 'REVOKE_ROLE', 'CREATE_ROLE', 'UPDATE_ROLE', 'DELETE_ROLE',
                'REGISTER_PERMISSION', 'CREATE_PRINCIPAL', 'UPDATE_PRINCIPAL', 'DEACTIVATE_PRINCIPAL',
                'CREATE_SERVICE_ACCOUNT', 'ROTATE_KEY', 'ISSUE_TOKEN', 'RESOLVE_PERMISSIONS',
                'PROVISION_WORKLOAD_PRINCIPAL')"));

        modelBuilder.Entity<RolePermission>()
            .HasOne(rp => rp.Role)
            .WithMany(r => r.RolePermissions)
            .HasForeignKey(rp => rp.RoleId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<RolePermission>()
            .HasOne(rp => rp.Permission)
            .WithMany(p => p.RolePermissions)
            .HasForeignKey(rp => rp.PermissionId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<PrincipalRoleBinding>()
            .HasOne(prb => prb.Principal)
            .WithMany(p => p.RoleBindings)
            .HasForeignKey(prb => prb.PrincipalId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<PrincipalRoleBinding>()
            .HasOne(prb => prb.Role)
            .WithMany(r => r.PrincipalBindings)
            .HasForeignKey(prb => prb.RoleId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<PrincipalPermissionBinding>()
            .HasOne(ppb => ppb.Principal)
            .WithMany(p => p.PermissionBindings)
            .HasForeignKey(ppb => ppb.PrincipalId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<PrincipalPermissionBinding>()
            .HasOne(ppb => ppb.Permission)
            .WithMany(p => p.PrincipalBindings)
            .HasForeignKey(ppb => ppb.PermissionId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
