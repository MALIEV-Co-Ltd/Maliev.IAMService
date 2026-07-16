using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.IAMService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class HardenWorkloadPrincipalProvisioning : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "performed_by",
                table: "workload_provisioning_operations",
                type: "uuid",
                nullable: true);

            migrationBuilder.Sql(
                """
                UPDATE workload_provisioning_operations AS operation
                SET performed_by = (
                    SELECT candidate.performed_by
                    FROM iamaudit_logs AS candidate
                    INNER JOIN principals AS actor ON actor.principal_id = candidate.performed_by
                    WHERE candidate.action = 'PROVISION_WORKLOAD_PRINCIPAL'
                      AND candidate.principal_id = operation.principal_id
                      AND candidate.details LIKE '%' || operation.operation_id::text || '%'
                      AND actor.is_active = TRUE
                      AND actor.principal_type = 'user'
                    ORDER BY candidate.timestamp DESC
                    LIMIT 1
                );

                DO $$
                BEGIN
                    IF EXISTS (SELECT 1 FROM workload_provisioning_operations WHERE performed_by IS NULL) THEN
                        RAISE EXCEPTION 'cannot attribute existing workload provisioning operations to an employee actor';
                    END IF;
                END;
                $$;
                """);

            migrationBuilder.AlterColumn<Guid>(
                name: "performed_by",
                table: "workload_provisioning_operations",
                type: "uuid",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_workload_provisioning_operations_principal_id",
                table: "workload_provisioning_operations",
                column: "principal_id");

            migrationBuilder.CreateIndex(
                name: "IX_workload_provisioning_operations_performed_by",
                table: "workload_provisioning_operations",
                column: "performed_by");

            migrationBuilder.AddForeignKey(
                name: "FK_workload_provisioning_operations_principals_principal_id",
                table: "workload_provisioning_operations",
                column: "principal_id",
                principalTable: "principals",
                principalColumn: "principal_id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_workload_provisioning_operations_principals_performed_by",
                table: "workload_provisioning_operations",
                column: "performed_by",
                principalTable: "principals",
                principalColumn: "principal_id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.Sql(
                """
                CREATE FUNCTION prevent_managed_workload_principal_delete() RETURNS trigger AS $$
                BEGIN
                    IF OLD.workload_id IS NOT NULL THEN
                        RAISE EXCEPTION 'managed workload principals cannot be deleted' USING ERRCODE = '23503';
                    END IF;
                    RETURN OLD;
                END;
                $$ LANGUAGE plpgsql;
                CREATE TRIGGER principals_managed_workload_delete_guard
                BEFORE DELETE ON principals
                FOR EACH ROW EXECUTE FUNCTION prevent_managed_workload_principal_delete();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                DROP TRIGGER IF EXISTS principals_managed_workload_delete_guard ON principals;
                DROP FUNCTION IF EXISTS prevent_managed_workload_principal_delete();
                """);

            migrationBuilder.DropForeignKey(
                name: "FK_workload_provisioning_operations_principals_principal_id",
                table: "workload_provisioning_operations");

            migrationBuilder.DropForeignKey(
                name: "FK_workload_provisioning_operations_principals_performed_by",
                table: "workload_provisioning_operations");

            migrationBuilder.DropIndex(
                name: "IX_workload_provisioning_operations_principal_id",
                table: "workload_provisioning_operations");

            migrationBuilder.DropIndex(
                name: "IX_workload_provisioning_operations_performed_by",
                table: "workload_provisioning_operations");

            migrationBuilder.DropColumn(
                name: "performed_by",
                table: "workload_provisioning_operations");
        }
    }
}
