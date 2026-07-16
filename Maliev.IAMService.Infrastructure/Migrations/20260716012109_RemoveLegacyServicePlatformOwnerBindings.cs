using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.IAMService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class RemoveLegacyServicePlatformOwnerBindings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                CREATE FUNCTION reject_nonhuman_platform_owner_binding() RETURNS trigger AS $$
                DECLARE
                    target_principal_type text;
                BEGIN
                    IF lower(NEW.role_id) <> 'roles.platform.owner' THEN
                        RETURN NEW;
                    END IF;

                    SELECT principal_type
                    INTO target_principal_type
                    FROM principals
                    WHERE principal_id = NEW.principal_id;

                    IF target_principal_type IS NOT NULL AND target_principal_type <> 'user' THEN
                        RAISE EXCEPTION 'roles.platform.owner is restricted to human user principals'
                            USING ERRCODE = '23514';
                    END IF;

                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;

                CREATE TRIGGER principal_role_bindings_human_platform_owner_only
                BEFORE INSERT OR UPDATE OF principal_id, role_id ON principal_role_bindings
                FOR EACH ROW EXECUTE FUNCTION reject_nonhuman_platform_owner_binding();

                CREATE FUNCTION reject_platform_owner_principal_type_change() RETURNS trigger AS $$
                BEGIN
                    IF NEW.principal_type <> 'user'
                       AND EXISTS (
                           SELECT 1
                           FROM principal_role_bindings
                           WHERE principal_id = NEW.principal_id
                             AND lower(role_id) = 'roles.platform.owner') THEN
                        RAISE EXCEPTION 'a Platform Owner principal must remain a human user'
                            USING ERRCODE = '23514';
                    END IF;

                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;

                CREATE TRIGGER principals_platform_owner_type_guard
                BEFORE UPDATE OF principal_type ON principals
                FOR EACH ROW EXECUTE FUNCTION reject_platform_owner_principal_type_change();

                DELETE FROM principal_role_bindings AS binding
                USING principals AS principal
                WHERE binding.principal_id = principal.principal_id
                  AND lower(binding.role_id) = 'roles.platform.owner'
                  AND principal.principal_type <> 'user';
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                DO $$
                BEGIN
                    RAISE EXCEPTION 'cannot roll back the human-only Platform Owner invariant safely'
                        USING ERRCODE = '55000';
                END;
                $$;
                """);
        }
    }
}
