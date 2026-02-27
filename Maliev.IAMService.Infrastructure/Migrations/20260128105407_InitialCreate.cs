using System;
using System.Net;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.IAMService.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "iamaudit_logs",
                columns: table => new
                {
                    log_id = table.Column<Guid>(type: "uuid", nullable: false),
                    action = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    principal_id = table.Column<Guid>(type: "uuid", nullable: true),
                    role_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    permission_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    performed_by = table.Column<Guid>(type: "uuid", nullable: false),
                    timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ip_address = table.Column<IPAddress>(type: "inet", nullable: true),
                    user_agent = table.Column<string>(type: "text", nullable: true),
                    details = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_iamaudit_logs", x => x.log_id);
                    table.CheckConstraint("CK_AuditLog_Action", "action IN ('GRANT_ROLE', 'REVOKE_ROLE', 'CREATE_ROLE', 'UPDATE_ROLE', 'DELETE_ROLE',\r\n                'REGISTER_PERMISSION', 'CREATE_PRINCIPAL', 'UPDATE_PRINCIPAL', 'DEACTIVATE_PRINCIPAL',\r\n                'CREATE_SERVICE_ACCOUNT', 'ROTATE_KEY', 'ISSUE_TOKEN', 'RESOLVE_PERMISSIONS')");
                });

            migrationBuilder.CreateTable(
                name: "permissions",
                columns: table => new
                {
                    permission_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    service_name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    resource_type = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    action = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    description = table.Column<string>(type: "text", nullable: true),
                    registered_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_permissions", x => x.permission_id);
                    table.CheckConstraint("CK_Permission_Format", "permission_id = '*' OR permission_id ~ '^[a-z0-9-]+\\.[a-z0-9-]+\\.[a-z0-9-]+$'");
                });

            migrationBuilder.CreateTable(
                name: "principals",
                columns: table => new
                {
                    principal_id = table.Column<Guid>(type: "uuid", nullable: false),
                    principal_type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    email = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    display_name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    linked_service = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    linked_entity_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_principals", x => x.principal_id);
                    table.CheckConstraint("CK_Principal_Type", "principal_type IN ('user', 'service_account')");
                });

            migrationBuilder.CreateTable(
                name: "roles",
                columns: table => new
                {
                    role_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    service_name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    role_name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    description = table.Column<string>(type: "text", nullable: true),
                    is_custom = table.Column<bool>(type: "boolean", nullable: false),
                    created_by = table.Column<Guid>(type: "uuid", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_roles", x => x.role_id);
                    table.CheckConstraint("CK_Role_Service", "(is_custom = TRUE) OR (service_name IS NOT NULL)");
                });

            migrationBuilder.CreateTable(
                name: "principal_permission_bindings",
                columns: table => new
                {
                    binding_id = table.Column<Guid>(type: "uuid", nullable: false),
                    principal_id = table.Column<Guid>(type: "uuid", nullable: false),
                    permission_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    resource_path = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    granted_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_principal_permission_bindings", x => x.binding_id);
                    table.ForeignKey(
                        name: "fk_principal_permission_bindings_permissions_permission_id",
                        column: x => x.permission_id,
                        principalTable: "permissions",
                        principalColumn: "permission_id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_principal_permission_bindings_principals_principal_id",
                        column: x => x.principal_id,
                        principalTable: "principals",
                        principalColumn: "principal_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "service_account_api_keys",
                columns: table => new
                {
                    key_id = table.Column<Guid>(type: "uuid", nullable: false),
                    principal_id = table.Column<Guid>(type: "uuid", nullable: false),
                    key_hash = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    key_prefix = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    last_used_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    expires_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    is_active = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_service_account_api_keys", x => x.key_id);
                    table.ForeignKey(
                        name: "fk_service_account_api_keys_principals_principal_id",
                        column: x => x.principal_id,
                        principalTable: "principals",
                        principalColumn: "principal_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "principal_role_bindings",
                columns: table => new
                {
                    binding_id = table.Column<Guid>(type: "uuid", nullable: false),
                    principal_id = table.Column<Guid>(type: "uuid", nullable: false),
                    role_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    resource_path = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    granted_by = table.Column<Guid>(type: "uuid", nullable: false),
                    granted_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_principal_role_bindings", x => x.binding_id);
                    table.ForeignKey(
                        name: "fk_principal_role_bindings_principals_principal_id",
                        column: x => x.principal_id,
                        principalTable: "principals",
                        principalColumn: "principal_id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_principal_role_bindings_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "roles",
                        principalColumn: "role_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "role_permissions",
                columns: table => new
                {
                    role_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    permission_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    added_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_role_permissions", x => new { x.role_id, x.permission_id });
                    table.ForeignKey(
                        name: "fk_role_permissions_permissions_permission_id",
                        column: x => x.permission_id,
                        principalTable: "permissions",
                        principalColumn: "permission_id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_role_permissions_roles_role_id",
                        column: x => x.role_id,
                        principalTable: "roles",
                        principalColumn: "role_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_iamaudit_logs_action",
                table: "iamaudit_logs",
                column: "action");

            migrationBuilder.CreateIndex(
                name: "IX_iamaudit_logs_performed_by",
                table: "iamaudit_logs",
                column: "performed_by");

            migrationBuilder.CreateIndex(
                name: "IX_iamaudit_logs_principal_id",
                table: "iamaudit_logs",
                column: "principal_id");

            migrationBuilder.CreateIndex(
                name: "IX_iamaudit_logs_timestamp",
                table: "iamaudit_logs",
                column: "timestamp",
                descending: new bool[0]);

            migrationBuilder.CreateIndex(
                name: "IX_permissions_permission_id",
                table: "permissions",
                column: "permission_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_permissions_resource_type",
                table: "permissions",
                column: "resource_type");

            migrationBuilder.CreateIndex(
                name: "IX_permissions_service_name",
                table: "permissions",
                column: "service_name");

            migrationBuilder.CreateIndex(
                name: "ix_principal_permission_bindings_permission_id",
                table: "principal_permission_bindings",
                column: "permission_id");

            migrationBuilder.CreateIndex(
                name: "IX_principal_permission_bindings_principal_id",
                table: "principal_permission_bindings",
                column: "principal_id");

            migrationBuilder.CreateIndex(
                name: "IX_principal_permission_bindings_principal_id_permission_id_re~",
                table: "principal_permission_bindings",
                columns: new[] { "principal_id", "permission_id", "resource_path" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_principal_role_bindings_expires_at",
                table: "principal_role_bindings",
                column: "expires_at",
                filter: "expires_at IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_principal_role_bindings_principal_id",
                table: "principal_role_bindings",
                column: "principal_id");

            migrationBuilder.CreateIndex(
                name: "IX_principal_role_bindings_principal_id_role_id_resource_path",
                table: "principal_role_bindings",
                columns: new[] { "principal_id", "role_id", "resource_path" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_principal_role_bindings_role_id",
                table: "principal_role_bindings",
                column: "role_id");

            migrationBuilder.CreateIndex(
                name: "IX_principals_email",
                table: "principals",
                column: "email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_role_permissions_permission_id",
                table: "role_permissions",
                column: "permission_id");

            migrationBuilder.CreateIndex(
                name: "IX_roles_is_custom",
                table: "roles",
                column: "is_custom");

            migrationBuilder.CreateIndex(
                name: "IX_roles_role_id",
                table: "roles",
                column: "role_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_roles_service_name",
                table: "roles",
                column: "service_name");

            migrationBuilder.CreateIndex(
                name: "IX_service_account_api_keys_key_prefix",
                table: "service_account_api_keys",
                column: "key_prefix");

            migrationBuilder.CreateIndex(
                name: "ix_service_account_api_keys_principal_id",
                table: "service_account_api_keys",
                column: "principal_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "iamaudit_logs");

            migrationBuilder.DropTable(
                name: "principal_permission_bindings");

            migrationBuilder.DropTable(
                name: "principal_role_bindings");

            migrationBuilder.DropTable(
                name: "role_permissions");

            migrationBuilder.DropTable(
                name: "service_account_api_keys");

            migrationBuilder.DropTable(
                name: "permissions");

            migrationBuilder.DropTable(
                name: "roles");

            migrationBuilder.DropTable(
                name: "principals");
        }
    }
}
