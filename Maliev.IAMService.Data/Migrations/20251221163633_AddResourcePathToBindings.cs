using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.IAMService.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddResourcePathToBindings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_principal_role_bindings_principal_id_role_id_resource_type_~",
                table: "principal_role_bindings");

            migrationBuilder.DropColumn(
                name: "resource_id",
                table: "principal_role_bindings");

            migrationBuilder.DropColumn(
                name: "resource_type",
                table: "principal_role_bindings");

            migrationBuilder.AddColumn<string>(
                name: "resource_path",
                table: "principal_role_bindings",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_principal_role_bindings_principal_id_role_id_resource_path",
                table: "principal_role_bindings",
                columns: new[] { "principal_id", "role_id", "resource_path" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_principal_role_bindings_principal_id_role_id_resource_path",
                table: "principal_role_bindings");

            migrationBuilder.DropColumn(
                name: "resource_path",
                table: "principal_role_bindings");

            migrationBuilder.AddColumn<string>(
                name: "resource_id",
                table: "principal_role_bindings",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "resource_type",
                table: "principal_role_bindings",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_principal_role_bindings_principal_id_role_id_resource_type_~",
                table: "principal_role_bindings",
                columns: new[] { "principal_id", "role_id", "resource_type", "resource_id" },
                unique: true);
        }
    }
}
