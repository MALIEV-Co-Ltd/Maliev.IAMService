using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.IAMService.Data.Migrations
{
    /// <inheritdoc />
    public partial class AllowSystemPrincipalType : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_Principal_Type",
                table: "principals");

            migrationBuilder.AddCheckConstraint(
                name: "CK_Principal_Type",
                table: "principals",
                sql: "principal_type IN ('user', 'service_account', 'system')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_Principal_Type",
                table: "principals");

            migrationBuilder.AddCheckConstraint(
                name: "CK_Principal_Type",
                table: "principals",
                sql: "principal_type IN ('user', 'service_account')");
        }
    }
}
