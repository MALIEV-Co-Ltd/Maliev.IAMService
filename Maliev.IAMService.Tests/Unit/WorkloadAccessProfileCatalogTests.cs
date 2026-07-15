using Maliev.IAMService.Application.Workloads;

namespace Maliev.IAMService.Tests.Unit;

public sealed class WorkloadAccessProfileCatalogTests
{
    [Fact]
    public void Constructor_WildcardPermission_RejectsProfile()
    {
        var profile = new WorkloadAccessProfile("unsafe", 1, "roles.workloads.unsafe.v1", ["*"]);

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([profile]));
    }

    [Fact]
    public void Constructor_PlatformOwnerRole_RejectsProfile()
    {
        var profile = new WorkloadAccessProfile("unsafe", 1, "roles.platform.owner", ["iam.auth.resolve-permissions"]);

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([profile]));
    }

    [Fact]
    public void Get_AuthServiceVersionOne_ReturnsExactLeastPrivilegePermissions()
    {
        var profile = WorkloadAccessProfileCatalog.Default.Get("auth-service", 1);

        Assert.Equal("roles.workloads.auth-service.v1", profile.RoleId);
        Assert.Equal(["iam.auth.resolve-permissions"], profile.Permissions);
    }
}
