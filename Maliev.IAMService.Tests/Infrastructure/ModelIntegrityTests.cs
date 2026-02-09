using Maliev.IAMService.Data;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Maliev.IAMService.Tests.Infrastructure;

/// <summary>
/// Verifies that the EF Core model matches the current migrations.
/// This prevents "Pending model changes" exceptions at runtime.
/// </summary>
public class ModelIntegrityTests
{
    [Fact]
    public void Model_ShouldNotHavePendingChanges()
    {
        // Use a dummy connection string just to build the model for comparison
        var options = new DbContextOptionsBuilder<IAMDbContext>()
            .UseNpgsql("Host=localhost;Database=ModelCheck")
            .Options;

        using var context = new IAMDbContext(options);

        // This helper (available in EF Core 9.0+) checks if the current code
        // matches the last snapshot in the Migrations folder.
        var hasChanges = context.Database.HasPendingModelChanges();

        Assert.False(hasChanges,
            "The EF Core model for 'IAMDbContext' has changed but no migration has been added. " +
            "Run 'dotnet ef migrations add <Name> --project Maliev.IAMService.Data --startup-project Maliev.IAMService.Api' to fix this.");
    }
}
