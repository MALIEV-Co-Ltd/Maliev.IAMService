using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.IAMService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddWorkloadPrincipalProvisioning : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_AuditLog_Action",
                table: "iamaudit_logs");

            migrationBuilder.AddColumn<string>(
                name: "workload_id",
                table: "principals",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "workload_provisioning_operations",
                columns: table => new
                {
                    operation_id = table.Column<Guid>(type: "uuid", nullable: false),
                    workload_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    profile_version = table.Column<int>(type: "integer", nullable: false),
                    request_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    principal_id = table.Column<Guid>(type: "uuid", nullable: false),
                    completed_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_workload_provisioning_operations", x => x.operation_id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_principals_workload_id",
                table: "principals",
                column: "workload_id",
                unique: true,
                filter: "workload_id IS NOT NULL");

            migrationBuilder.AddCheckConstraint(
                name: "CK_Principal_WorkloadId",
                table: "principals",
                sql: "workload_id IS NULL OR workload_id ~ '^[a-z0-9]+(-[a-z0-9]+)*$'");

            migrationBuilder.Sql(
                """
                CREATE FUNCTION prevent_workload_id_mutation() RETURNS trigger AS $$
                BEGIN
                    IF OLD.workload_id IS NOT NULL AND NEW.workload_id IS DISTINCT FROM OLD.workload_id THEN
                        RAISE EXCEPTION 'workload_id is immutable' USING ERRCODE = '23514';
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
                CREATE TRIGGER principals_workload_id_immutable
                BEFORE UPDATE OF workload_id ON principals
                FOR EACH ROW EXECUTE FUNCTION prevent_workload_id_mutation();
                """);

            migrationBuilder.AddCheckConstraint(
                name: "CK_AuditLog_Action",
                table: "iamaudit_logs",
                sql: "action IN ('GRANT_ROLE', 'REVOKE_ROLE', 'CREATE_ROLE', 'UPDATE_ROLE', 'DELETE_ROLE',\r\n                'REGISTER_PERMISSION', 'CREATE_PRINCIPAL', 'UPDATE_PRINCIPAL', 'DEACTIVATE_PRINCIPAL',\r\n                'CREATE_SERVICE_ACCOUNT', 'ROTATE_KEY', 'ISSUE_TOKEN', 'RESOLVE_PERMISSIONS',\n                'PROVISION_WORKLOAD_PRINCIPAL')");

            migrationBuilder.CreateIndex(
                name: "IX_workload_provisioning_operations_workload_id_profile_version",
                table: "workload_provisioning_operations",
                columns: new[] { "workload_id", "profile_version" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "workload_provisioning_operations");

            migrationBuilder.DropIndex(
                name: "IX_principals_workload_id",
                table: "principals");

            migrationBuilder.Sql(
                """
                DROP TRIGGER IF EXISTS principals_workload_id_immutable ON principals;
                DROP FUNCTION IF EXISTS prevent_workload_id_mutation();
                """);

            migrationBuilder.DropCheckConstraint(
                name: "CK_Principal_WorkloadId",
                table: "principals");

            migrationBuilder.DropCheckConstraint(
                name: "CK_AuditLog_Action",
                table: "iamaudit_logs");

            migrationBuilder.DropColumn(
                name: "workload_id",
                table: "principals");

            migrationBuilder.AddCheckConstraint(
                name: "CK_AuditLog_Action",
                table: "iamaudit_logs",
                sql: "action IN ('GRANT_ROLE', 'REVOKE_ROLE', 'CREATE_ROLE', 'UPDATE_ROLE', 'DELETE_ROLE',\n                'REGISTER_PERMISSION', 'CREATE_PRINCIPAL', 'UPDATE_PRINCIPAL', 'DEACTIVATE_PRINCIPAL',\n                'CREATE_SERVICE_ACCOUNT', 'ROTATE_KEY', 'ISSUE_TOKEN', 'RESOLVE_PERMISSIONS')");
        }
    }
}
