using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace Maliev.IAMService.Data.Configurations;

/// <summary>
/// Extension methods for configuring Entity Framework Core to use snake_case naming conventions.
/// </summary>
public static partial class SnakeCaseNamingExtensions
{
    /// <summary>
    /// Configures the model builder to use snake_case naming for tables, columns, keys, and indexes.
    /// </summary>
    /// <param name="modelBuilder">The model builder instance.</param>
    public static void UseSnakeCaseNaming(this ModelBuilder modelBuilder)
    {
        foreach (var entity in modelBuilder.Model.GetEntityTypes())
        {
            // Convert table names to snake_case
            entity.SetTableName(ToSnakeCase(entity.GetTableName() ?? entity.ClrType.Name));

            // Convert column names to snake_case
            foreach (var property in entity.GetProperties())
            {
                property.SetColumnName(ToSnakeCase(property.Name));
            }

            // Convert primary key names
            foreach (var key in entity.GetKeys())
            {
                key.SetName(ToSnakeCase(key.GetName() ?? $"PK_{entity.ClrType.Name}"));
            }

            // Convert foreign key names
            foreach (var foreignKey in entity.GetForeignKeys())
            {
                foreignKey.SetConstraintName(ToSnakeCase(foreignKey.GetConstraintName() ?? $"FK_{entity.ClrType.Name}"));
            }

            // Convert index names
            foreach (var index in entity.GetIndexes())
            {
                index.SetDatabaseName(ToSnakeCase(index.GetDatabaseName() ?? $"IX_{entity.ClrType.Name}"));
            }
        }
    }

    private static string ToSnakeCase(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;

        var startUnderscores = MyRegex().Match(input);
        return startUnderscores + MyRegex1().Replace(input, "$1_$2").ToLower();
    }

    [GeneratedRegex("^_+")]
    private static partial Regex MyRegex();

    [GeneratedRegex("([a-z0-9])([A-Z])")]
    private static partial Regex MyRegex1();
}
