using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Maliev.IAMService.Infrastructure.Persistence;

/// <summary>
/// Factory for creating <see cref="IAMDbContext"/> instances at design time (e.g. for migrations).
/// </summary>
public class IAMDbContextFactory : IDesignTimeDbContextFactory<IAMDbContext>
{
    /// <summary>
    /// Creates a new instance of <see cref="IAMDbContext"/>.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>A new instance of <see cref="IAMDbContext"/>.</returns>
    public IAMDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IAMDbContext>();
        optionsBuilder.UseNpgsql("Host=localhost;Database=iam_service;");
        return new IAMDbContext(optionsBuilder.Options);
    }
}
