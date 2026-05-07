namespace Maliev.IAMService.Tests.Unit;

/// <summary>
/// Source-level guard tests for first-user bootstrap safety.
/// </summary>
public class BootstrapSourceGuardTests
{
    /// <summary>
    /// Aspire synthetic owners must not block first real Google Workspace owner bootstrap.
    /// </summary>
    [Fact]
    public void BootstrapQueries_ExcludeAspireTestAdminSeederPrincipal()
    {
        var consumerSource = File.ReadAllText(FindSource("Maliev.IAMService.Api", "Consumers", "EmployeeCreatedConsumer.cs"));
        var principalsSource = File.ReadAllText(FindSource("Maliev.IAMService.Api", "Controllers", "PrincipalsController.cs"));

        Assert.Contains("AspireTestAdminSeeder", consumerSource, StringComparison.Ordinal);
        Assert.Contains("AspireTestAdminSeeder", principalsSource, StringComparison.Ordinal);
        Assert.Contains("p.LinkedService != AspireTestAdminLinkedService", consumerSource, StringComparison.Ordinal);
        Assert.Contains("p.LinkedService != AspireTestAdminLinkedService", principalsSource, StringComparison.Ordinal);
        Assert.Contains("callerPrincipal.LinkedService == AspireTestAdminLinkedService", principalsSource, StringComparison.Ordinal);
        Assert.Contains("Aspire automation principal cannot be promoted to Platform Owner.", principalsSource, StringComparison.Ordinal);
    }

    private static string FindSource(params string[] segments)
    {
        foreach (var startDirectory in new[] { AppContext.BaseDirectory, Environment.CurrentDirectory })
        {
            var directory = new DirectoryInfo(startDirectory);
            while (directory is not null)
            {
                var candidates = new[]
                {
                    Path.Combine(new[] { directory.FullName }.Concat(segments).ToArray()),
                    Path.Combine(new[] { directory.FullName, "Maliev.IAMService" }.Concat(segments).ToArray())
                };

                foreach (var candidate in candidates)
                {
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }

                directory = directory.Parent;
            }
        }

        throw new FileNotFoundException($"Unable to locate source file {string.Join("/", segments)}.");
    }
}
