using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Maliev.IAMService.Data;

public class IAMDbContextFactory : IDesignTimeDbContextFactory<IAMDbContext>
{
    public IAMDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IAMDbContext>();

        // Use a dummy connection string for migrations
        optionsBuilder.UseNpgsql("Host=localhost;Database=iam_service;");

        return new IAMDbContext(optionsBuilder.Options);
    }
}
